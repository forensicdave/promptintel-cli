"""Opt-in, read-only CLI checks using Community and Enterprise credentials.

Raw API responses and child-process logs stay in memory and never enter reports.
Only /check uses POST, for one fixed indicator per key; nothing is submitted.
"""

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from promptintel_cli import __version__
from promptintel_cli.client import API_URL, SCANNER_URL, ClientError
from promptintel_cli.credentials import CredentialStore, validate_profile

DEFAULT_KEYS = Path.home() / ".config/promptintel-cli/test-keys.json"
DEFAULT_REPORT = ROOT / ".test-results/live.json"


@dataclass(frozen=True)
class Case:
    name: str
    command: tuple[str, ...]
    enterprise_only: bool = False


PUBLIC_CASES = (
    Case("health", ("health",)),
    Case("public_keys", ("keys",)),
)
PLAN_CASES = (
    Case("limits", ("limits",)),
    Case("quota", ("quota",)),
    Case("feed", ("feed",)),
    Case("prompts", ("prompts", "list", "--limit", "1")),
    Case("indicator_check", ("check", "example.com")),
    Case("artifacts", ("artifacts", "list", "--limit", "1"), True),
    Case("detection_rules", ("detection-rules", "--limit", "1"), True),
    Case("rules_manifest", ("rules", "manifest"), True),
    Case("rules_download", ("rules", "download", "--raw"), True),
    Case("taxii_discovery", ("taxii", "discovery"), True),
)
CASE_NAMES = tuple(case.name for case in (*PUBLIC_CASES, *PLAN_CASES))


class ConfigurationError(Exception):
    pass


def load_keys(path):
    """Do not include exception details: malformed JSON could contain a secret."""
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(65537)
            mode = stat.S_IMODE(os.fstat(handle.fileno()).st_mode)
        if len(raw) > 65536:
            raise ConfigurationError("The key file exceeds the 64 KiB limit.")
        values = json.loads(raw)
    except (OSError, ValueError, UnicodeError) as exc:
        raise ConfigurationError("Cannot read the key file as JSON. Check --keys-file and its contents.") from exc
    return validate_keys(values), bool(mode & 0o077)


def validate_keys(values):
    if not isinstance(values, dict):
        raise ConfigurationError("The key file must be an object with community and enterprise keys.")
    keys = {}
    for plan in ("community", "enterprise"):
        value = values.get(plan)
        if not isinstance(value, str) or not re.fullmatch(r"ak_[A-Za-z0-9_-]{8,}", value.strip()):
            raise ConfigurationError("Both community and enterprise must contain valid-looking ak_ credentials.")
        keys[plan] = value.strip()
    if keys["community"] == keys["enterprise"]:
        raise ConfigurationError("Community and Enterprise credentials must be different.")
    return keys


def load_keyring_keys(community_profile, enterprise_profile):
    # Explicit profiles bypass the environment override so both plans are tested
    # with the intended credentials. Only the child process receives its own key.
    try:
        profiles = {"community": validate_profile(community_profile), "enterprise": validate_profile(enterprise_profile)}
        store = CredentialStore()
        values = {plan: store.get(profile) for plan, profile in profiles.items()}
        if any(value is None for value in values.values()):
            raise ConfigurationError("Both keyring profiles must exist. Save them with auth set --profile NAME first.")
        return validate_keys(values)
    except ClientError as exc:
        raise ConfigurationError(str(exc)) from None


def data_object(payload):
    return payload.get("data", payload) if isinstance(payload, dict) else None


def record_list(payload, *names):
    data = data_object(payload)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for name in names:
            if isinstance(data.get(name), list):
                return data[name]
    return None


def json_from_stderr(stderr):
    # The CLI prefixes its own debug/progress lines; JSON strings escape newlines.
    body = b"\n".join(line for line in stderr.splitlines() if not line.startswith((b"INFO ", b"DEBUG ")))
    try:
        value = json.loads(body)
        return value if isinstance(value, dict) else {}
    except (ValueError, UnicodeError):
        return {}


def enterprise_denial_evidence(error):
    """Recognize an Enterprise requirement without depending on one error schema.

    JSON APIs may use error, code, or a nested error object; TAXII errors use
    title/description/error_code. Never return remote free text to the report.
    An arbitrary 403 (invalid key, WAF refusal, etc.) is not enough to pass.
    """
    if not isinstance(error, dict):
        return None
    fields = ("error", "code", "error_code", "message", "title", "description", "detail")
    values = []
    for field in fields:
        value = error.get(field)
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, dict):
            values.extend(item for key, item in value.items() if key in fields and isinstance(item, str))
    for value in values:
        # Normalize code separators as well as whitespace in human-readable errors.
        normalized = re.sub(r"[_\s-]+", " ", value.strip().lower())
        if normalized in {"enterprise required", "enterprise plan required", "enterprise access required", "enterprise subscription required"}:
            return "enterprise_requirement"
        patterns = (
            r"\b(?:requires?|requiring|needs?)\b[^.!?\n]{0,100}\benterprise\b",
            r"\benterprise(?:\s+(?:plan|access|subscription|account|tier|license))?\s+(?:is\s+)?required\b",
            r"\benterprise(?:\s+(?:plans?|accounts?|subscriptions?|users?|customers?))?\s+only\b",
            r"\bonly\b[^.!?\n]{0,60}\benterprise\b",
            r"\b(?:available|restricted|limited|exclusive)\s+(?:only\s+)?(?:to|for|on)\s+(?:the\s+)?enterprise\b",
            r"\bupgrade\s+(?:your\s+\w+\s+)?to\s+(?:the\s+)?enterprise\b",
        )
        if any(re.search(pattern, normalized) for pattern in patterns):
            return "enterprise_requirement"
    return None


def denial_diagnostics(error, result):
    """Bounded structural facts only: no error strings, codes, or record content."""
    return {
        "stdout_empty": not result.stdout,
        "stderr_json_object": bool(error),
        "error_field_type": type(error.get("error")).__name__,
        "present_error_fields": [field for field in ("error", "code", "error_code", "message", "title", "description", "detail") if field in error],
        "enterprise_requirement_recognized": enterprise_denial_evidence(error) is not None,
        "traceback_detected": b"Traceback (most recent call last)" in result.stderr,
    }


class LiveRunner:
    def __init__(self, keys, *, interval=4.0, timeout=20.0, execute=subprocess.run,
                 sleep=time.sleep, clock=time.monotonic, progress=print,
                 plans=("community", "enterprise"), cases=None):
        self.keys = keys
        self.interval = interval
        self.timeout = timeout
        self.execute = execute
        self.sleep = sleep
        self.clock = clock
        self.progress = progress
        self.results = []
        self.last_start = None
        self.stop_all = False
        self.stop_plans = set()
        self.pack_sha256 = None
        self.plans = tuple(plans)
        self.cases = frozenset(CASE_NAMES if cases is None else cases)

    def matrix(self):
        matrix = [("public", case) for case in PUBLIC_CASES if case.name in self.cases]
        selected = {case.name for case in PLAN_CASES if case.name in self.cases}
        for plan in self.plans:
            names = selected.copy()
            if names:
                names.add("limits")  # Always verify a key's effective plan first.
            if plan == "enterprise" and "rules_download" in names:
                names.add("rules_manifest")
            matrix.extend((plan, case) for case in PLAN_CASES if case.name in names)
        return matrix

    def record(self, plan, case, status, message, *, cli_exit_code=None, http_status=None, diagnostics=None):
        # All messages originate in this program, not in remote response content.
        row = {"plan": plan, "case": case.name, "status": status, "message": message}
        if cli_exit_code is not None:
            row["cli_exit_code"] = cli_exit_code
        if http_status is not None:
            row["http_status"] = http_status
        if diagnostics is not None:
            row["diagnostics"] = diagnostics
        self.results.append(row)
        self.progress(f"{status.upper():12} {plan:10} {case.name}: {message}")

    def check_response(self, plan, case, payload, raw):
        """Return a status and a fixed explanation; never return response values."""
        data = data_object(payload)
        if case.name == "health":
            return ("pass", "Public health request succeeded.") if isinstance(payload, dict) else ("fail", "Health response is not a JSON object.")
        if case.name == "public_keys":
            valid = isinstance(data, dict) and isinstance(data.get("keys"), list)
            return ("pass", "Public JWK set returned.") if valid else ("fail", "Public JWK response has no keys array.")
        if case.name == "limits":
            if not isinstance(data, dict) or not isinstance(data.get("plan"), str):
                self.stop_plans.add(plan)
                return "inconclusive", "Account response does not identify its plan; remaining checks for this key skipped."
            if data["plan"].lower() != plan:
                self.stop_plans.add(plan)
                return "fail", "Effective account plan differs from the key's label; remaining checks for this key skipped."
            return "pass", "Account plan matches the credential label."
        if case.name == "quota":
            return ("pass", "Scanner quota returned.") if isinstance(data, dict) else ("fail", "Scanner quota is not a JSON object.")
        if case.name == "feed":
            rows = record_list(payload, "items", "threats")
            access = payload.get("access") if isinstance(payload, dict) else None
            if isinstance(data, dict):
                access = data.get("access", access)
            if rows is None or any(not isinstance(row, dict) for row in rows):
                return "fail", "Feed has no recognizable array of records."
            expected = "summary" if plan == "community" else "full"
            if access is not None and access != expected:
                return "fail", "Feed access marker does not match the account plan."
            if plan == "community":
                if any(row.get("indicators_withheld") is not True for row in rows):
                    return "fail", "Community feed does not mark every returned item's indicators as withheld."
                if any(row.get("iocs") or row.get("indicators") for row in rows):
                    return "fail", "Community feed unexpectedly includes indicator values."
            elif any(row.get("indicators_withheld") is True for row in rows):
                return "fail", "Enterprise feed unexpectedly withholds indicators."
            if access is None and (not rows or plan == "enterprise"):
                return "inconclusive", "Feed returned, but full access cannot be established from its markers."
            return "pass", "Feed access and withholding markers match the account plan."
        if case.name == "prompts":
            rows = record_list(payload, "items", "prompts")
            if rows is None or any(not isinstance(row, dict) for row in rows):
                return "fail", "Prompt listing has no recognizable array of records."
            if not rows:
                return "inconclusive", "Prompt list is empty; text visibility cannot be tested."
            text_fields = ("prompt", "prompt_text", "text", "prompt_base64")
            if plan == "community":
                if any(row.get("text_withheld") is not True for row in rows):
                    return "fail", "Community prompt listing does not mark attack text as withheld."
                if any(any(row.get(field) for field in (*text_fields, "nova_rule", "nova_rule_base64")) for row in rows):
                    return "fail", "Community prompt listing unexpectedly includes attack text or a NOVA rule."
            else:
                if any(row.get("text_withheld") is True for row in rows):
                    return "fail", "Enterprise prompt listing unexpectedly withholds attack text."
                if not any(any(row.get(field) for field in text_fields) for row in rows):
                    return "inconclusive", "Enterprise listing returned, but no recognized attack-text field was present."
            return "pass", "Prompt text visibility matches the account plan."
        if case.name == "indicator_check":
            if not isinstance(data, dict) or data.get("detail") != ("summary" if plan == "community" else "full"):
                return "fail", "Indicator detail marker does not match the account plan."
            rows = data.get("results")
            if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
                return "fail", "Expected exactly one indicator result."
            allowed = {"known", "unknown"} if plan == "community" else {"block", "require_approval", "warn", "log", "unknown"}
            verdict = rows[0].get("verdict")
            if not isinstance(verdict, str) or verdict not in allowed:
                return "fail", "Indicator result has an unexpected verdict for this plan."
            if plan == "community" and rows[0].get("matches"):
                return "fail", "Community indicator result unexpectedly includes matching records."
            source = data.get("source", {})
            if isinstance(source, dict) and (source.get("complete") is False or source.get("stale") is True or source.get("prompt_indicators") in ("partial", "unavailable")):
                return "inconclusive", "Check succeeded, but the API reports partial or stale source intelligence."
            return "pass", "One indicator checked with the expected response detail; this is not a safety verdict."
        if case.name in ("artifacts", "detection_rules"):
            rows = record_list(payload, "items", "artifacts", "rules")
            return ("pass", "Enterprise listing succeeded.") if rows is not None else ("fail", "Enterprise listing has no recognizable array of records.")
        if case.name == "rules_manifest":
            digest = data.get("sha256") if isinstance(data, dict) else None
            if isinstance(digest, str):
                digest = digest.removeprefix("sha256:").lower()
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                return "fail", "Rule manifest has no valid SHA-256 for download verification."
            self.pack_sha256 = digest
            return "pass", "Enterprise manifest supplies a rule-pack checksum."
        if case.name == "rules_download":
            if hashlib.sha256(raw).hexdigest() != self.pack_sha256:
                return "fail", "Downloaded rule bytes do not match the manifest checksum."
            return "pass", "Native rule download matches the manifest SHA-256; rules were not executed."
        if case.name == "taxii_discovery":
            valid = isinstance(data, dict) and isinstance(data.get("api_roots"), list) and bool(data["api_roots"])
            return ("pass", "Enterprise TAXII discovery returned API roots.") if valid else ("fail", "TAXII discovery has no API roots.")
        return "fail", "No validator exists for this test case."

    def run_case(self, plan, case):
        if self.stop_all or plan in self.stop_plans:
            self.record(plan, case, "skipped", "An earlier blocking condition stopped these requests.")
            return
        if case.name == "rules_download" and plan == "enterprise" and self.pack_sha256 is None:
            self.record(plan, case, "skipped", "A valid manifest checksum is required before downloading the rule pack.")
            return
        if self.last_start is not None:
            self.sleep(max(0, self.interval - (self.clock() - self.last_start)))
        argv = [sys.executable, "-m", "promptintel_cli", "--format", "json", "--debug", "--verbose",
                "--api-url", API_URL, "--scanner-url", SCANNER_URL, "--timeout", str(self.timeout), *case.command]
        if case.name == "rules_download" and plan == "enterprise":
            argv += ["--sha256", self.pack_sha256]
        env = os.environ.copy()
        env.pop("PROMPTINTEL_API_KEY", None)
        if plan != "public":
            env["PROMPTINTEL_API_KEY"] = self.keys[plan]
        self.progress(f"CHECK        {plan:10} {case.name}")
        self.last_start = self.clock()
        try:
            result = self.execute(argv, cwd=ROOT, env=env, capture_output=True, timeout=self.timeout + 5)
        except subprocess.TimeoutExpired:
            self.stop_all = True
            self.record(plan, case, "blocked", "CLI timed out; remaining requests stopped and no retry attempted.")
            return
        except OSError:
            self.stop_all = True
            self.record(plan, case, "blocked", "Could not start the CLI; remaining requests stopped.")
            return

        combined = result.stdout + b"\n" + result.stderr
        if any(key.encode() in combined for key in self.keys.values()) or re.search(rb"\bak_[A-Za-z0-9_-]+", combined):
            self.stop_all = True
            self.record(plan, case, "fail", "A credential was detected in CLI output; raw output discarded and tests stopped.")
            return
        status_matches = re.findall(rb"^INFO HTTP (\d{3})\b", result.stderr, re.MULTILINE)
        http_status = int(status_matches[-1]) if status_matches else None
        details = {"cli_exit_code": result.returncode, "http_status": http_status}
        error = json_from_stderr(result.stderr) if result.returncode else {}
        if http_status == 429 or result.returncode == 4:
            self.stop_all = True
            self.record(plan, case, "blocked", "Rate limit reached; wait before another run. No retries were attempted.", **details)
            return
        if (http_status is not None and http_status >= 500) or (http_status is None and b"Network request failed" in result.stderr):
            self.stop_all = True
            self.record(plan, case, "blocked", "API or network unavailable; remaining requests stopped without retrying.", **details)
            return
        if http_status == 401:
            self.stop_plans.add(plan)
        if case.enterprise_only and plan == "community":
            diagnostics = denial_diagnostics(error, result)
            valid = (result.returncode == 3 and http_status == 403 and diagnostics["enterprise_requirement_recognized"]
                     and diagnostics["stdout_empty"] and not diagnostics["traceback_detected"])
            if result.returncode != 3 or http_status != 403:
                message = "Expected HTTP 403 and CLI exit 3 for the Community access denial."
            elif not diagnostics["stdout_empty"]:
                message = "Community access denial unexpectedly wrote to stdout."
            elif diagnostics["traceback_detected"]:
                message = "Community access denial unexpectedly emitted a traceback."
            elif not diagnostics["enterprise_requirement_recognized"]:
                message = "HTTP 403 and exit 3 are correct, but the error does not identify a recognized Enterprise requirement; see report diagnostics."
            else:
                message = "Expected Community access denial returned correctly."
            self.record(plan, case, "pass" if valid else "fail",
                        message, diagnostics=diagnostics, **details)
            return
        if result.returncode != 0 or http_status is None or not 200 <= http_status < 300:
            if case.name == "limits":
                self.stop_plans.add(plan)
            self.record(plan, case, "fail", "CLI did not return the expected successful HTTP response.", **details)
            return
        if re.search(rb"Traceback \(most recent call last\)", result.stderr):
            self.record(plan, case, "fail", "CLI unexpectedly emitted a traceback.", **details)
            return
        raw = case.name == "rules_download"
        try:
            payload = None if raw else json.loads(result.stdout)
        except (ValueError, UnicodeError):
            self.record(plan, case, "fail", "Successful stdout is not valid JSON.", **details)
            return
        status, message = self.check_response(plan, case, payload, result.stdout)
        self.record(plan, case, status, message, **details)

    def run(self):
        started = datetime.now(timezone.utc).isoformat()
        interrupted = False
        try:
            for plan, case in self.matrix():
                self.run_case(plan, case)
        except KeyboardInterrupt:
            interrupted = True
            self.progress("Interrupted; saving completed outcomes only.")
        counts = {status: 0 for status in ("pass", "fail", "blocked", "inconclusive", "skipped")}
        counts.update(Counter(row["status"] for row in self.results))
        exit_code = 130 if interrupted else 1 if counts["fail"] else 3 if any(counts[s] for s in ("blocked", "inconclusive", "skipped")) else 0
        return {"schema_version": 1, "tool_version": __version__, "started_at": started,
                "requested_plans": list(self.plans), "requested_cases": sorted(self.cases),
                "finished_at": datetime.now(timezone.utc).isoformat(), "interrupted": interrupted,
                "summary": counts, "exit_code": exit_code, "results": self.results}


def write_report(path, report):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write((json.dumps(report, indent=2, ensure_ascii=True) + "\n").encode())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def positive_number(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return number


def selected_cases(value):
    if value == "all":
        return None
    names = value.split(",")
    if not names or any(name not in CASE_NAMES for name in names):
        raise argparse.ArgumentTypeError("use all or comma-separated case names: " + ", ".join(CASE_NAMES))
    return tuple(dict.fromkeys(names))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    credentials = parser.add_mutually_exclusive_group()
    credentials.add_argument("--keys-file", type=Path, help="Private JSON key file (default: ~/.config/promptintel-cli/test-keys.json)")
    credentials.add_argument("--keyring", action="store_true", help="Read both keys from OS credential-store profiles instead of a file")
    parser.add_argument("--community-profile", help="Profile used with --keyring (default: community)")
    parser.add_argument("--enterprise-profile", help="Profile used with --keyring (default: enterprise)")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--interval", type=positive_number, default=4.0, help="Minimum seconds between requests (default: 4)")
    parser.add_argument("--timeout", type=positive_number, default=20.0, help="Per-request socket timeout (default: 20)")
    parser.add_argument("--plan", choices=("both", "community", "enterprise"), default="both", help="Select credentials to test (default: both)")
    parser.add_argument("--cases", type=selected_cases, default=None, help="all, or comma-separated test names; limits and required rule manifests are added automatically")
    args = parser.parse_args(argv)
    try:
        if not args.keyring and (args.community_profile is not None or args.enterprise_profile is not None):
            raise ConfigurationError("Profile options require --keyring.")
        keys_path = (args.keys_file or DEFAULT_KEYS).expanduser().resolve()
        report_path = args.report.expanduser().resolve()
        if keys_path == report_path or (report_path.exists() and keys_path.exists() and keys_path.samefile(report_path)):
            raise ConfigurationError("The report must not overwrite the private key file.")
        if args.keyring:
            keys = load_keyring_keys(args.community_profile or "community", args.enterprise_profile or "enterprise")
            loose_permissions = False
        else:
            keys, loose_permissions = load_keys(keys_path)
        if loose_permissions:
            print("NOTE: key file permissions allow other local users access; restrict it with chmod 600.", file=sys.stderr)
        plans = ("community", "enterprise") if args.plan == "both" else (args.plan,)
        runner = LiveRunner(keys, interval=args.interval, timeout=args.timeout, plans=plans, cases=args.cases)
        matrix = runner.matrix()
        checks = sum(case.name == "indicator_check" for _, case in matrix)
        print(f"Read-only live tests: at most {len(matrix)} requests, including {checks} indicator checks in total.")
        print("Raw responses, credentials, and threat content are never written to the report.")
        report = runner.run()
        write_report(report_path, report)
        print("Summary: " + ", ".join(f"{count} {name}" for name, count in report["summary"].items()))
        print("Saved sanitized JSON report.")
        return report["exit_code"]
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    except OSError:
        print("Cannot access the configured input or report location. Check paths and permissions.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
