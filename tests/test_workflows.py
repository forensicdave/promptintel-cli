"""End-to-end CLI workflows with a bounded, ordered fake HTTP transport."""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError
from urllib.parse import parse_qs, urlsplit

from promptintel_cli.cli import main
from tests.test_cli import FakeResponse, TEST_KEY


class SequenceOpener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        try:
            response = next(self.responses)
        except StopIteration:
            raise AssertionError("Unexpected extra HTTP request") from None
        if isinstance(response, Exception):
            raise response
        return response


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {"PROMPTINTEL_API_KEY": TEST_KEY}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def invoke(self, argv, responses=(), stdin=""):
        opener = SequenceOpener(responses)
        out, err = io.StringIO(), io.StringIO()
        with patch("promptintel_cli.client.build_opener", return_value=opener), \
                patch("sys.stdin", io.StringIO(stdin)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*argv, "--format", "json"])
        self.assertNotIn(TEST_KEY, out.getvalue() + err.getvalue())
        return code, out.getvalue(), err.getvalue(), opener.requests

    def test_doctor_checks_both_services_and_reports_plan_without_credentials(self):
        for plan in ("community", "enterprise"):
            with self.subTest(plan=plan), tempfile.TemporaryDirectory() as directory:
                headers = Path(directory) / "headers.json"
                responses = [FakeResponse({"data": {"status": "healthy"}}),
                             FakeResponse({"data": {"plan": plan, "echo": TEST_KEY}}),
                             FakeResponse({"data": {"scans": {"left": 10}}},
                                          headers={"X-RateLimit-Remaining": "95", "Set-Cookie": "omit"})]
                code, out, err, requests = self.invoke(["doctor", "--headers-output", str(headers), "--debug"], responses)
                report = json.loads(out)
                self.assertEqual(code, 0, err)
                self.assertTrue(report["ok"])
                self.assertTrue(report["api_key_configured"])
                self.assertEqual([row["status"] for row in report["checks"]], ["ok"] * 3)
                self.assertEqual(report["checks"][1]["response"]["data"]["plan"], plan)
                self.assertIsNone(requests[0].get_header("Authorization"))
                self.assertEqual(requests[1].get_header("Authorization"), "Bearer " + TEST_KEY)
                self.assertEqual([urlsplit(req.full_url).path for req in requests],
                                 ["/api/v1/health", "/api/v1/agents/me/limits", "/scanner-api/v1/quota"])
                self.assertEqual(json.loads(headers.read_text())["scanner_quota"], {"x-ratelimit-remaining": "95"})

    def test_doctor_missing_key_still_checks_public_connectivity(self):
        with patch.dict(os.environ, {}, clear=True):
            code, out, err, requests = self.invoke(["doctor"], [FakeResponse({"data": {"status": "ok"}})])
        self.assertEqual(code, 3, err)
        report = json.loads(out)
        self.assertFalse(report["api_key_configured"])
        self.assertFalse(report["ok"])
        self.assertEqual(len(requests), 1)
        self.assertEqual([row["reason"] for row in report["checks"][1:]], ["missing_api_key"] * 2)

    def test_doctor_continues_independent_checks_after_network_or_auth_error(self):
        responses = [URLError("offline " + TEST_KEY),
                     FakeResponse({"error": "invalid_key"}, status=401),
                     FakeResponse({"data": {"scans": {"left": 0}}})]
        code, out, err, requests = self.invoke(["doctor"], responses)
        self.assertEqual(code, 3, err)
        self.assertEqual(len(requests), 3)
        self.assertEqual([row["status"] for row in json.loads(out)["checks"]], ["error", "error", "ok"])

    def test_doctor_stops_after_rate_limit_and_keeps_retry_guidance(self):
        response = FakeResponse({"error": "too_many_requests"}, status=429, headers={"Retry-After": "60"})
        code, out, err, requests = self.invoke(["doctor"], [response])
        self.assertEqual(code, 4, err)
        checks = json.loads(out)["checks"]
        self.assertEqual(checks[0]["error"]["retry_after"], "60")
        self.assertEqual([row["status"] for row in checks], ["error", "skipped", "skipped"])
        self.assertEqual(len(requests), 1)

    def test_doctor_rejects_account_response_without_plan(self):
        responses = [FakeResponse({"data": {"status": "ok"}}), FakeResponse({"data": {}}),
                     FakeResponse({"data": {"scans": {}}})]
        code, out, err, _ = self.invoke(["doctor"], responses)
        self.assertEqual(code, 1, err)
        self.assertFalse(json.loads(out)["ok"])

    def test_check_combines_positional_typed_file_and_stdin_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "indicators.txt"
            source.write_bytes(b"\xef\xbb\xbffile.example\r\n\r\n  other.example  \r\n")
            code, _, err, requests = self.invoke(
                ["check", "arg.example", "--indicator", "package=lodash.merge", "--input", str(source),
                 "--input", "-", "--type", "domain"], [FakeResponse()],
                '{"indicators": ["stdin.example", {"type": "extension", "value": "ms-python.python"}]}')
        self.assertEqual(code, 0, err)
        self.assertEqual(len(requests), 1)
        self.assertEqual(json.loads(requests[0].data)["indicators"], [
            {"type": "domain", "value": "arg.example"}, {"type": "package", "value": "lodash.merge"},
            {"type": "domain", "value": "file.example"}, {"type": "domain", "value": "other.example"},
            {"type": "domain", "value": "stdin.example"}, {"type": "extension", "value": "ms-python.python"}])

    def test_json_array_input_and_explicit_text_format_support_get(self):
        for stdin, options, expected in (
            ('["one.example", "two.example"]', [], {"value": ["one.example", "two.example"]}),
            ('[{"type":"package","value":"lodash.merge"}]', [], {"value": ["lodash.merge"], "type": ["package"]}),
            ('[2001:db8::1]\n', ["--input-format", "text"], {"value": ["[2001:db8::1]"]}),
        ):
            with self.subTest(stdin=stdin):
                code, _, err, requests = self.invoke(["check", "--input", "-", "--method", "get", *options], [FakeResponse()], stdin)
                self.assertEqual(code, 0, err)
                self.assertEqual(parse_qs(urlsplit(requests[0].full_url).query), expected)
                self.assertIsNone(requests[0].data)

    def test_indicator_input_errors_send_nothing_and_never_echo_content(self):
        cases = [([], ""), ([], "[]"), ([], "{bad json"),
                 ([], '{"indicators": [], "extra": 1}'), ([], '[{"type":"wrong","value":"x"}]'),
                 ([], '[{"type":"package","value":"x","extra":1}]'), ([], '[null]'),
                 ([], '["line\\ncontrol"]'), ([], json.dumps([TEST_KEY])), ([], "ak_fake_credential"),
                 (["--input", "-"], "example.com"), ([], "\n".join(["x.example"] * 101)),
                 (["arg.example"], json.dumps(["x.example"] * 100)),
                 (["--input-format", "json"], '"example.com"')]
        for options, stdin in cases:
            with self.subTest(options=options, input_length=len(stdin)):
                code, out, _, requests = self.invoke(["check", *options, "--input", "-"], stdin=stdin)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertEqual(requests, [])

    def test_unreadable_or_invalid_utf8_input_is_an_input_error(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "invalid.txt"
            source.write_bytes(b"\xff")
            for path in (source, Path(directory) / "missing.txt"):
                code, _, _, requests = self.invoke(["check", "--input", str(path)])
                self.assertEqual(code, 2)
                self.assertEqual(requests, [])

    def test_policy_is_opt_in_and_preserves_response_on_match(self):
        for verdict in ("block", "require_approval", "warn", "log", "known", "unknown"):
            for enabled in (False, True):
                with self.subTest(verdict=verdict, enabled=enabled):
                    payload = {"data": {"results": [{"value": "example.com", "verdict": verdict}]}}
                    flags = ["--fail-on", verdict] if enabled else []
                    code, out, err, _ = self.invoke(["check", "example.com", *flags], [FakeResponse(payload)])
                    self.assertEqual(code, 6 if enabled else 0, err)
                    self.assertEqual(json.loads(out), payload)

    def test_policy_matches_any_result_and_saves_output_with_exit_six(self):
        payload = {"data": {"results": [{"verdict": "unknown"}, {"verdict": "block"}]}}
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "results.json"
            code, out, err, _ = self.invoke(["check", "a.example", "b.example", "--method", "get",
                                           "--fail-on", "block,require_approval", "-o", str(destination)], [FakeResponse(payload)])
            self.assertEqual(code, 6, err)
            self.assertEqual(out, "")
            self.assertEqual(json.loads(destination.read_text()), payload)

    def test_policy_unknown_and_incomplete_are_explicit(self):
        for source in ({"complete": False}, {"stale": True}, {"prompt_indicators": "partial"},
                       {"prompt_indicators": "unavailable"}, {"agent_files": "unavailable"}):
            for policy, expected in (("block,warn", 0), ("unknown", 6), ("incomplete", 6)):
                with self.subTest(source=source, policy=policy):
                    payload = {"data": {"results": [{"verdict": "unknown"}], "source": source}}
                    code, _, err, _ = self.invoke(["check", "example.com", "--fail-on", policy], [FakeResponse(payload)])
                    self.assertEqual(code, expected, err)

    def test_scan_policy_uses_verdict_not_static_signal(self):
        for data, selected, expected in (
            ({"verdict": "malicious"}, "suspicious,malicious", 6),
            ({"verdict": "clean", "static_signal": "malicious"}, "malicious", 0),
            ({"verdict": None, "static_signal": "clean"}, "incomplete", 6),
            ({"verdict": None}, "unknown", 6),
            ({"verdict": "clean", "deep_review_completed": False}, "incomplete", 6),
        ):
            with self.subTest(data=data, selected=selected):
                code, out, err, _ = self.invoke(["scans", "get", "a" * 64, "--fail-on", selected], [FakeResponse({"data": data})])
                self.assertEqual(code, expected, err)
                self.assertEqual(json.loads(out)["data"], data)

    def test_new_scan_and_local_scan_support_policy_without_bypassing_consent(self):
        payload = {"data": {"verdict": "suspicious"}}
        code, _, err, _ = self.invoke(["scan", "example.com", "--private", "--fail-on", "suspicious"], [FakeResponse(payload)])
        self.assertEqual(code, 6, err)
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "SKILL.md").write_text("Example skill")
            args = ["scan-files", "SKILL.md", "--root", directory, "--kind", "skill", "--fail-on", "suspicious"]
            code, _, _, requests = self.invoke(args)
            self.assertEqual(code, 5)
            self.assertEqual(requests, [])
            code, _, err, _ = self.invoke([*args, "--yes"], [FakeResponse(payload)])
            self.assertEqual(code, 6, err)

    def test_invalid_policy_fails_before_request(self):
        for command, value in ((["check", "example.com"], "clean"), (["check", "example.com"], "block,"),
                               (["check", "example.com"], ""), (["scan", "example.com"], "known")):
            code, out, _, requests = self.invoke([*command, "--fail-on", value])
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertEqual(requests, [])

    def test_malformed_policy_results_are_errors_and_http_errors_take_priority(self):
        for data in ({}, {"results": []}, {"results": [{"verdict": "safe"}]},
                     {"results": [{"verdict": {}}]}, {"results": [{"verdict": "unknown"}] * 2},
                     {"results": [{"verdict": "unknown"}], "source": []}):
            code, out, _, _ = self.invoke(["check", "example.com", "--fail-on", "block"], [FakeResponse({"data": data})])
            self.assertEqual(code, 1)
            self.assertEqual(out, "")
        for status, expected in ((403, 3), (429, 4)):
            code, out, _, requests = self.invoke(["check", "example.com", "--fail-on", "unknown"],
                                                [FakeResponse({"error": "refused"}, status=status)])
            self.assertEqual(code, expected)
            self.assertEqual(out, "")
            self.assertEqual(len(requests), 1)

    def test_default_listing_still_returns_one_unchanged_page(self):
        payload = {"data": [{"id": "1"}], "pagination": {"has_more": True}}
        code, out, err, requests = self.invoke(["prompts", "list"], [FakeResponse(payload)])
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out), payload)
        self.assertEqual(len(requests), 1)

    def test_page_pagination_preserves_envelopes_filters_and_headers(self):
        pages = [{"data": [{"id": str(page)}], "pagination": {"totalPages": 3}, "access": "summary"} for page in (2, 3)]
        with tempfile.TemporaryDirectory() as directory:
            headers = Path(directory) / "headers.json"
            code, out, err, requests = self.invoke(["prompts", "list", "--page", "2", "--limit", "1", "--severity", "high",
                                                   "--all", "--headers-output", str(headers)],
                                                  [FakeResponse(page, headers={"ETag": str(i)}) for i, page in enumerate(pages)])
            self.assertEqual(code, 0, err)
            report = json.loads(out)
            self.assertEqual(report["pages"], pages)
            self.assertTrue(report["pagination"]["complete"])
            self.assertIsNone(report["pagination"]["next_query"])
            self.assertEqual([parse_qs(urlsplit(req.full_url).query) for req in requests],
                             [{"page": [str(page)], "limit": ["1"], "severity": ["high"]} for page in (2, 3)])
            self.assertEqual(json.loads(headers.read_text()), {"pages": [{"etag": "0"}, {"etag": "1"}]})

    def test_max_pages_caps_requests_and_returns_resume_query(self):
        for flags, count in (([], 5), (["--max-pages", "2"], 2)):
            with self.subTest(flags=flags):
                responses = [FakeResponse({"data": [{"id": str(i)}]}) for i in range(count)]
                code, out, err, requests = self.invoke(["artifacts", "list", "--all", "--limit", "1", "--severity", "high", *flags], responses)
                self.assertEqual(code, 0, err)
                self.assertEqual(len(requests), count)
                self.assertEqual(json.loads(out)["pagination"], {"pages_fetched": count, "max_pages": count,
                                 "complete": False, "stop_reason": "max_pages", "next_query": {"page": count + 1, "limit": 1, "severity": "high"}})

    def test_max_pages_requires_all_and_a_bounded_positive_number(self):
        for flags in (["--max-pages", "2"], ["--all", "--max-pages", "0"], ["--all", "--max-pages", "101"]):
            code, _, _, requests = self.invoke(["prompts", "list", *flags])
            self.assertEqual(code, 2)
            self.assertEqual(requests, [])

    def test_offset_pagination_advances_by_rows_and_keeps_access_metadata(self):
        pages = [{"data": [{"id": "1"}, {"id": "2"}], "access": {"can_submit": True}},
                 {"data": [{"id": "3"}], "access": {"can_submit": True}}]
        code, out, err, requests = self.invoke(["submissions", "list", "--offset", "4", "--limit", "2", "--all"],
                                               [FakeResponse(page) for page in pages])
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["pages"], pages)
        self.assertEqual([parse_qs(urlsplit(req.full_url).query)["offset"] for req in requests], [["4"], ["6"]])

    def test_detection_rule_cursor_is_only_a_query_value(self):
        cursor = "https://elsewhere.example/path?x=1&y=2"
        pages = [{"data": [{"id": "1"}], "pagination": {"next": cursor}},
                 {"data": [{"id": "2"}], "pagination": {"next": None}}]
        code, out, err, requests = self.invoke(["detection-rules", "--limit", "1", "--all"], [FakeResponse(page) for page in pages])
        self.assertEqual(code, 0, err)
        self.assertTrue(json.loads(out)["pagination"]["complete"])
        self.assertEqual(urlsplit(requests[1].full_url).hostname, "api.promptintel.securitybreak.io")
        self.assertEqual(parse_qs(urlsplit(requests[1].full_url).query), {"limit": ["1"], "after": [cursor]})

    def test_prompt_indicators_propagates_both_cursor_fields(self):
        cursor = {"before": "2026-11-27T10:00:00+00:00", "before_id": "record&1"}
        pages = [{"data": [{"id": "1"}], "next": cursor}, {"data": [], "next": None}]
        code, _, err, requests = self.invoke(["prompts", "indicators", "--all"], [FakeResponse(page) for page in pages])
        self.assertEqual(code, 0, err)
        self.assertEqual(parse_qs(urlsplit(requests[1].full_url).query), {key: [value] for key, value in cursor.items()})

    def test_taxii_objects_and_manifest_preserve_filters_and_more(self):
        for command in ("objects", "manifest"):
            with self.subTest(command=command):
                pages = [{"objects": [{"id": "indicator--1"}], "more": True, "next": "cursor+1"},
                         {"objects": [], "more": False}]
                code, out, err, requests = self.invoke(["taxii", command, "agent-files", "--all", "--match-type", "indicator",
                                                       "--added-after", "2026-11-01"], [FakeResponse(page) for page in pages])
                self.assertEqual(code, 0, err)
                self.assertEqual(json.loads(out)["pages"], pages)
                self.assertEqual(parse_qs(urlsplit(requests[1].full_url).query),
                                 {"match[type]": ["indicator"], "added_after": ["2026-11-01"], "next": ["cursor+1"]})
                self.assertEqual(requests[1].get_header("Accept"), "application/taxii+json;version=2.1")

    def test_repeated_or_missing_cursors_fail_without_claiming_completeness(self):
        cases = [(["detection-rules"], [{"data": [{"id": "1"}]}]),
                 (["detection-rules"], [{"data": [], "pagination": {"next": "same"}}] * 2),
                 (["prompts", "indicators"], [{"data": [], "next": {"before": "date"}}]),
                 (["taxii", "objects", "agent-files"], [{"objects": [], "more": True}]),
                 (["taxii", "objects", "agent-files"], [{"data": []}]),
                 (["prompts", "list"], [{"data": [], "pagination": {"has_more": True}}]),
                 (["prompts", "list"], [{"data": [], "pagination": {"next_page": 1}}])]
        for command, pages in cases:
            with self.subTest(command=command, pages=pages):
                code, out, _, requests = self.invoke([*command, "--all"], [FakeResponse(page) for page in pages])
                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertEqual(len(requests), len(pages))

    def test_page_failure_stops_without_retry_or_overwriting_existing_files(self):
        for status, expected in ((429, 4), (500, 1)):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                output, headers = Path(directory) / "out.json", Path(directory) / "headers.json"
                output.write_text("previous result")
                headers.write_text("previous headers")
                pages = [FakeResponse({"data": [{"id": "1"}], "pagination": {"has_more": True}}),
                         FakeResponse({"error": "refused"}, status=status, headers={"Retry-After": "60"})]
                code, out, err, requests = self.invoke(["prompts", "list", "--all", "-o", str(output), "--headers-output", str(headers)], pages)
                self.assertEqual(code, expected)
                self.assertEqual(len(requests), 2)
                self.assertEqual(out, "")
                self.assertEqual(json.loads(err)["pagination"], {"pages_fetched": 1, "failed_query": {"page": 2}})
                self.assertEqual(output.read_text(), "previous result")
                self.assertEqual(headers.read_text(), "previous headers")

    def test_pagination_has_an_aggregate_memory_bound(self):
        with patch("promptintel_cli.pagination.MAX_RESPONSE_BYTES", 10):
            code, out, err, requests = self.invoke(["prompts", "list", "--all"], [FakeResponse({"data": [{"id": "1"}]})])
        self.assertEqual(code, 1)
        self.assertIn("aggregate", json.loads(err)["message"])
        self.assertEqual(out, "")
        self.assertEqual(len(requests), 1)
