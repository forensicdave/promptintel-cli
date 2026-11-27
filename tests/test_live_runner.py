import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.test_live import ConfigurationError, LiveRunner, PLAN_CASES, load_keys, main, selected_cases, write_report

KEYS = {"community": "ak_test_community_secret_123", "enterprise": "ak_test_enterprise_secret_456"}
RULE_BYTES = b"rule HarmlessFixture { }\n"
CHECKSUM = hashlib.sha256(RULE_BYTES).hexdigest()


class FakeCLI:
    """Simulate the CLI process; these tests never read real credentials or use HTTP."""

    def __init__(self, overrides=None):
        self.overrides = overrides or {}
        self.calls = []

    def __call__(self, argv, **kwargs):
        command = tuple(argv[argv.index("--timeout") + 2:])
        key = kwargs["env"].get("PROMPTINTEL_API_KEY")
        plan = next((name for name, value in KEYS.items() if key == value), "public")
        name = next((case.name for case in PLAN_CASES if command[:len(case.command)] == case.command), command[0])
        if name == "keys":
            name = "public_keys"
        self.calls.append((plan, name, argv, kwargs))
        override = self.overrides.get((plan, name))
        if override is not None:
            if isinstance(override, Exception):
                raise override
            return override
        if plan == "community" and name in {"artifacts", "detection_rules", "rules_manifest", "rules_download", "taxii_discovery"}:
            return result({"error": "enterprise_required", "message": "Access denied"}, status=403, code=3)
        fixtures = {
            "health": {"data": {"status": "ok"}},
            "public_keys": {"keys": []},
            "limits": {"data": {"plan": plan}},
            "quota": {"data": {"checks": {"left": 5}}},
            "feed": {"access": "summary" if plan == "community" else "full", "data": [
                {"title": "private fixture text", "indicators_withheld": plan == "community"}]},
            "prompts": {"data": [{"text_withheld": True} if plan == "community" else {"prompt": "untrusted fixture text"}]},
            "indicator_check": {"data": {"detail": "summary" if plan == "community" else "full", "results": [
                {"verdict": "unknown", "matches": []}], "source": {"complete": True, "stale": False}}},
            "artifacts": {"data": []},
            "detection_rules": {"data": []},
            "rules_manifest": {"data": {"sha256": CHECKSUM}},
            "taxii_discovery": {"api_roots": ["https://api.example/root/"]},
        }
        return result(raw=RULE_BYTES) if name == "rules_download" else result(fixtures[name])


def result(payload=None, *, status=200, code=0, raw=None):
    log = f"INFO HTTP {status} in 0.01s (100 bytes)\n".encode() if status is not None else b""
    encoded = json.dumps(payload).encode() if raw is None else raw
    return subprocess.CompletedProcess([], code, encoded if code == 0 else b"", log + (encoded if code else b""))


class LiveRunnerTests(unittest.TestCase):
    def run_matrix(self, fake=None):
        fake = fake or FakeCLI()
        progress = []
        runner = LiveRunner(KEYS, interval=0, execute=fake, sleep=lambda _: None, progress=progress.append)
        return runner.run(), fake, progress

    def test_two_plan_matrix_includes_expected_denials_and_valid_checksum(self):
        report, fake, progress = self.run_matrix()
        self.assertEqual(report["exit_code"], 0, report)
        self.assertEqual(report["summary"]["pass"], 22)
        self.assertEqual(len(fake.calls), 22)
        for plan, _, argv, kwargs in fake.calls:
            self.assertNotIn(KEYS["community"], argv)
            self.assertNotIn(KEYS["enterprise"], argv)
            if plan == "public":
                self.assertNotIn("PROMPTINTEL_API_KEY", kwargs["env"])
            else:
                self.assertEqual(kwargs["env"]["PROMPTINTEL_API_KEY"], KEYS[plan])
        download = next(call for call in fake.calls if call[:2] == ("enterprise", "rules_download"))
        self.assertEqual(download[2][-2:], ["--sha256", CHECKSUM])
        output = json.dumps(report) + "\n".join(progress)
        for forbidden in (*KEYS.values(), "private fixture text", "untrusted fixture text", "https://api.example"):
            self.assertNotIn(forbidden, output)

    def test_wrong_account_plan_skips_its_remaining_tests(self):
        fake = FakeCLI({("community", "limits"): result({"data": {"plan": "enterprise"}})})
        report, fake, _ = self.run_matrix(fake)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual([name for plan, name, _, _ in fake.calls if plan == "community"], ["limits"])
        self.assertEqual(report["summary"]["skipped"], 9)
        self.assertEqual(len([1 for plan, _, _, _ in fake.calls if plan == "enterprise"]), 10)

    def test_429_stops_all_requests_without_retry(self):
        fake = FakeCLI({("community", "quota"): result({"error": "daily_limit_reached"}, status=429, code=4)})
        report, fake, _ = self.run_matrix(fake)
        self.assertEqual(report["exit_code"], 3)
        self.assertEqual(report["summary"]["blocked"], 1)
        self.assertEqual(len(fake.calls), 4)
        self.assertEqual(fake.calls[-1][:2], ("community", "quota"))

    def test_network_failure_stops_before_any_authenticated_request(self):
        fake = FakeCLI({("public", "health"): result({"error": "client_error", "message": "Network request failed: DNS failure"}, status=None, code=1)})
        report, fake, _ = self.run_matrix(fake)
        self.assertEqual(report["exit_code"], 3)
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(report["summary"]["skipped"], 21)

    def test_bad_403_and_unexpected_community_success_are_failures(self):
        for response in (result({"error": "different_error"}, status=403, code=3), result({"data": []})):
            with self.subTest(response=response):
                report, _, _ = self.run_matrix(FakeCLI({("community", "artifacts"): response}))
                self.assertEqual(report["exit_code"], 1)
                row = next(row for row in report["results"] if row["plan"] == "community" and row["case"] == "artifacts")
                self.assertEqual(row["status"], "fail")

    def test_enterprise_denials_support_code_text_nested_and_taxii_formats(self):
        payloads = (
            {"error": "Enterprise plan required"},
            {"error": "Forbidden", "code": "enterprise_required"},
            {"error": {"code": "enterprise_required", "message": "Denied"}},
            {"error": "Forbidden", "message": "This endpoint requires an Enterprise subscription."},
            {"title": "Forbidden", "description": "An Enterprise plan is required to use this API."},
            {"title": "Forbidden", "error_code": "enterprise_required"},
            {"error": "Available on Enterprise plans."},
            {"error": "This feature is for Enterprise accounts only."},
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                fake = FakeCLI({("community", name): result(payload, status=403, code=3)
                                for name in ("rules_manifest", "rules_download", "taxii_discovery")})
                report, _, _ = self.run_matrix(fake)
                self.assertEqual(report["exit_code"], 0, report)

    def test_unknown_denial_reports_structure_without_remote_content(self):
        payload = {"error": "a private error explanation", "title": "a private title"}
        report, _, progress = self.run_matrix(FakeCLI({("community", "rules_manifest"): result(payload, status=403, code=3)}))
        row = next(row for row in report["results"] if row["plan"] == "community" and row["case"] == "rules_manifest")
        self.assertEqual(row["status"], "fail")
        self.assertEqual(row["diagnostics"]["error_field_type"], "str")
        self.assertEqual(row["diagnostics"]["present_error_fields"], ["error", "title"])
        self.assertFalse(row["diagnostics"]["enterprise_requirement_recognized"])
        self.assertTrue(row["diagnostics"]["stdout_empty"])
        self.assertNotIn("a private error explanation", json.dumps(report) + "".join(progress))
        self.assertNotIn("a private title", json.dumps(report) + "".join(progress))

    def test_denial_with_stdout_or_traceback_still_fails(self):
        for stdout, extra_stderr in ((b"unexpected output", b""), (b"", b"\nTraceback (most recent call last):\n")):
            response = result({"error": "enterprise_required"}, status=403, code=3)
            response.stdout = stdout
            response.stderr += extra_stderr
            report, _, _ = self.run_matrix(FakeCLI({("community", "rules_manifest"): response}))
            self.assertEqual(report["exit_code"], 1)

    def test_focused_community_rerun_keeps_plan_check_and_spends_no_indicators(self):
        fake = FakeCLI()
        runner = LiveRunner(KEYS, interval=0, execute=fake, sleep=lambda _: None, progress=lambda _: None,
                            plans=("community",), cases=("rules_manifest", "rules_download", "taxii_discovery"))
        report = runner.run()
        self.assertEqual(report["exit_code"], 0, report)
        self.assertEqual([call[:2] for call in fake.calls], [
            ("community", "limits"), ("community", "rules_manifest"),
            ("community", "rules_download"), ("community", "taxii_discovery")])
        self.assertEqual(report["summary"]["pass"], 4)

    def test_focused_enterprise_download_adds_checksum_prerequisite(self):
        fake = FakeCLI()
        runner = LiveRunner(KEYS, interval=0, execute=fake, sleep=lambda _: None, progress=lambda _: None,
                            plans=("enterprise",), cases=("rules_download",))
        report = runner.run()
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual([name for _, name, _, _ in fake.calls], ["limits", "rules_manifest", "rules_download"])

    def test_focused_public_checks_do_not_use_either_credential(self):
        fake = FakeCLI()
        runner = LiveRunner(KEYS, interval=0, execute=fake, sleep=lambda _: None, progress=lambda _: None,
                            cases=("health", "public_keys"))
        self.assertEqual(runner.run()["exit_code"], 0)
        self.assertEqual([plan for plan, _, _, _ in fake.calls], ["public", "public"])
        self.assertEqual(selected_cases("rules_manifest,rules_download"), ("rules_manifest", "rules_download"))
        self.assertIsNone(selected_cases("all"))

    def test_empty_prompt_list_is_inconclusive_not_a_false_pass(self):
        report, _, _ = self.run_matrix(FakeCLI({("enterprise", "prompts"): result({"data": []})}))
        self.assertEqual(report["exit_code"], 3)
        self.assertEqual(report["summary"]["inconclusive"], 1)

    def test_community_content_leak_is_failed_without_copying_content_to_report(self):
        payload = {"data": [{"text_withheld": True, "prompt": "sensitive attack example"}]}
        report, _, progress = self.run_matrix(FakeCLI({("community", "prompts"): result(payload)}))
        self.assertEqual(report["exit_code"], 1)
        self.assertNotIn("sensitive attack example", json.dumps(report) + "".join(progress))

    def test_malformed_verdict_is_a_failure_not_a_crash(self):
        payload = {"data": {"detail": "full", "results": [{"verdict": {"unexpected": "object"}}]}}
        report, _, _ = self.run_matrix(FakeCLI({("enterprise", "indicator_check"): result(payload)}))
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["summary"]["fail"], 1)

    def test_key_leak_in_stdout_or_debug_stops_and_is_never_reported(self):
        for response in (result({"data": KEYS["enterprise"]}), subprocess.CompletedProcess([], 0, b"{}", KEYS["community"].encode())):
            with self.subTest(response=response):
                report, fake, progress = self.run_matrix(FakeCLI({("public", "health"): response}))
                self.assertEqual(report["exit_code"], 1)
                self.assertEqual(len(fake.calls), 1)
                for key in KEYS.values():
                    self.assertNotIn(key, json.dumps(report) + "".join(progress))

    def test_missing_manifest_checksum_skips_download(self):
        report, fake, _ = self.run_matrix(FakeCLI({("enterprise", "rules_manifest"): result({"data": {"rules": []}})}))
        self.assertEqual(report["exit_code"], 1)
        self.assertNotIn(("enterprise", "rules_download"), [call[:2] for call in fake.calls])

    def test_bad_native_checksum_fails(self):
        report, _, _ = self.run_matrix(FakeCLI({("enterprise", "rules_download"): result(raw=b"different bytes")}))
        self.assertEqual(report["exit_code"], 1)
        row = next(row for row in report["results"] if row["plan"] == "enterprise" and row["case"] == "rules_download")
        self.assertEqual(row["status"], "fail")

    def test_timeout_stops_the_suite_without_printing_exception_output(self):
        error = subprocess.TimeoutExpired([KEYS["community"]], 25, output=KEYS["enterprise"].encode())
        report, fake, progress = self.run_matrix(FakeCLI({("public", "health"): error}))
        self.assertEqual(report["exit_code"], 3)
        self.assertEqual(len(fake.calls), 1)
        self.assertNotIn(KEYS["enterprise"], json.dumps(report) + "".join(progress))

    def test_default_pacing_and_fixed_api_destinations(self):
        delays = []
        fake = FakeCLI()
        with patch.dict(os.environ, {"PROMPTINTEL_API_URL": "https://other.example", "PROMPTINTEL_API_KEY": "inherited"}):
            runner = LiveRunner(KEYS, execute=fake, sleep=delays.append, clock=lambda: 0, progress=lambda _: None)
            runner.run()
        self.assertEqual(delays, [4.0] * 21)
        for _, _, argv, _ in fake.calls:
            self.assertEqual(argv[argv.index("--api-url") + 1], "https://api.promptintel.securitybreak.io/api/v1")
            self.assertEqual(argv[argv.index("--scanner-url") + 1], "https://promptintel.securitybreak.io/scanner-api/v1")

    def test_key_file_errors_are_generic_and_report_cannot_overwrite_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys.json"
            path.write_text(json.dumps(KEYS))
            path.chmod(0o600)
            keys, loose = load_keys(path)
            self.assertEqual(keys, KEYS)
            self.assertFalse(loose)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main(["--keys-file", str(path), "--report", str(path)]), 2)
            self.assertEqual(json.loads(path.read_text()), KEYS)
            self.assertNotIn(KEYS["community"], stderr.getvalue())
            path.write_text('{"community": "' + KEYS["community"])
            with self.assertRaises(ConfigurationError) as caught:
                load_keys(path)
            self.assertNotIn(KEYS["community"], str(caught.exception))

    def test_report_is_private_and_preserves_structured_outcomes(self):
        report, _, _ = self.run_matrix()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reports/live.json"
            write_report(path, report)
            self.assertEqual(json.loads(path.read_text()), report)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
