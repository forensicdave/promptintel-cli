"""Opt-in policy decisions, separate from HTTP and authentication exit codes."""

from .client import ClientError

CHECK_VERDICTS = frozenset(("block", "require_approval", "warn", "log", "known", "unknown"))
SCAN_VERDICTS = frozenset(("clean", "suspicious", "malicious", "unknown"))
POLICY_COMMANDS = {"check", "scan", "scan-files", "scans get"}
POLICY_EXIT = 6


def parse_fail_on(value, command):
    selected = {item.strip() for item in value.split(",")}
    allowed = (CHECK_VERDICTS if command == "check" else SCAN_VERDICTS) | {"incomplete"}
    if not selected or not selected <= allowed:
        raise ClientError("--fail-on accepts comma-separated values: " + ", ".join(sorted(allowed)), code=2)
    return selected


def evaluate(payload, command, selected, *, expected_results=None):
    """Return 6 on a selected match; malformed decision data is an error, not 0."""
    if not selected:
        return 0
    data = payload.get("data", payload) if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise ClientError("Cannot evaluate --fail-on: expected a verdict object")
    observed = set()
    if command == "check":
        rows = data.get("results")
        if (not isinstance(rows, list) or not rows
                or (expected_results is not None and len(rows) != expected_results)):
            raise ClientError("Cannot evaluate --fail-on: missing or incomplete indicator result set")
        for row in rows:
            verdict = row.get("verdict") if isinstance(row, dict) else None
            if not isinstance(verdict, str) or verdict not in CHECK_VERDICTS:
                raise ClientError("Cannot evaluate --fail-on: unrecognized indicator verdict")
            observed.add(verdict)
        source = data.get("source", {})
        if not isinstance(source, dict):
            raise ClientError("Cannot evaluate --fail-on: malformed source metadata")
        if (source.get("complete") is False or source.get("stale") is True
                or source.get("prompt_indicators") in ("partial", "unavailable")
                or source.get("agent_files") in ("partial", "unavailable")):
            observed.add("incomplete")
    else:
        if "verdict" not in data:
            raise ClientError("Cannot evaluate --fail-on: scan has no verdict field")
        verdict = data["verdict"]
        if verdict is not None and (not isinstance(verdict, str) or verdict not in SCAN_VERDICTS):
            raise ClientError("Cannot evaluate --fail-on: unrecognized scan verdict")
        observed.add(verdict or "unknown")
        if verdict is None or data.get("deep_review_completed") is False:
            observed.add("incomplete")
    return POLICY_EXIT if selected & observed else 0
