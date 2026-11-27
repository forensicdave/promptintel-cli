import contextlib
import hashlib
from http.client import HTTPMessage, IncompleteRead
import io
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

from promptintel_cli.cli import build_parser, main, prepare_request
from promptintel_cli.client import Client, ClientError, NoRedirects
from promptintel_cli.endpoints import ENDPOINTS
from promptintel_cli.output import render


TEST_KEY = "test-credential-do-not-print"


class FakeResponse(io.BytesIO):
    def __init__(self, payload=None, *, status=200, headers=None, raw=None):
        super().__init__(raw if raw is not None else json.dumps(payload or {"data": []}).encode())
        self.code = status
        self.headers = HTTPMessage()
        for key, value in (headers or {"Content-Type": "application/json"}).items():
            self.headers[key] = value


class FakeOpener:
    def __init__(self, response=None, error=None):
        self.response = response or FakeResponse()
        self.error = error
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if self.error:
            raise self.error
        return self.response


class CLITests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"PROMPTINTEL_API_KEY": TEST_KEY}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def invoke(self, argv, response=None, stdin="", error=None):
        opener = FakeOpener(response, error)
        out, err = io.StringIO(), io.StringIO()
        with patch("promptintel_cli.client.build_opener", return_value=opener), patch("sys.stdin", io.StringIO(stdin)), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue(), opener

    def test_feed_options_and_log_streams(self):
        payload = {"success": True, "data": [{"title": "sample"}], "access": "summary"}
        code, out, err, opener = self.invoke(["--format", "json", "--verbose", "feed", "--severity", "high", "--since", "2026-11-01", "--debug"], FakeResponse(payload))
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out), payload)
        request = opener.requests[0][0]
        self.assertEqual(urlsplit(request.full_url).hostname, "api.promptintel.securitybreak.io")
        self.assertEqual(parse_qs(urlsplit(request.full_url).query), {"severity": ["high"], "since": ["2026-11-01"]})
        self.assertEqual(request.get_header("Authorization"), "Bearer " + TEST_KEY)
        self.assertIn("DEBUG", err)
        self.assertNotIn(TEST_KEY, out + err)
        self.assertNotIn("2026-11-01", err)

    def test_health_and_keys_work_without_key_and_never_send_auth(self):
        for command in ("health", "keys"):
            with self.subTest(command=command), patch.dict(os.environ, {}, clear=True):
                code, out, err, opener = self.invoke([command, "--format", "json"])
                self.assertEqual(code, 0, err)
                self.assertIsNone(opener.requests[0][0].get_header("Authorization"))

    def test_auth_required_before_any_network_or_consent(self):
        with patch.dict(os.environ, {}, clear=True):
            code, out, err, opener = self.invoke(["feed", "--format", "json"])
        self.assertEqual(code, 3)
        self.assertEqual(opener.requests, [])
        self.assertIn("PROMPTINTEL_API_KEY", json.loads(err)["message"])
        self.assertEqual(out, "")

    def test_check_typed_post_and_get_repeated_values(self):
        code, _, err, opener = self.invoke(["check", "example.com", "--indicator", "package=lodash.merge"])
        self.assertEqual(code, 0, err)
        request = opener.requests[0][0]
        self.assertIn("/scanner-api/v1/check", request.full_url)
        self.assertEqual(json.loads(request.data), {"indicators": ["example.com", {"type": "package", "value": "lodash.merge"}]})
        code, _, err, opener = self.invoke(["check", "a.example", "b.example", "--method", "get"])
        self.assertEqual(code, 0, err)
        self.assertEqual(parse_qs(urlsplit(opener.requests[0][0].full_url).query), {"value": ["a.example", "b.example"]})
        self.assertIsNone(opener.requests[0][0].data)
        code, _, err, opener = self.invoke(["check", "lodash.merge", "--type", "package", "--method", "get"])
        self.assertEqual(code, 0, err)
        self.assertEqual(parse_qs(urlsplit(opener.requests[0][0].full_url).query)["type"], ["package"])

    def test_check_rejects_invalid_input_without_request(self):
        for args in ([], ["a.example"] * 101, ["secret\nprompt"], [TEST_KEY], ["--indicator", "invalid=x"], ["a", "b", "--type", "package", "--method", "get"]):
            with self.subTest(args=args):
                code, _, err, opener = self.invoke(["check", *args])
                self.assertEqual(code, 2, err)
                self.assertEqual(opener.requests, [])
                self.assertNotIn(TEST_KEY, err)

    def test_rate_limit_preserves_details_and_does_not_retry(self):
        response = FakeResponse({"error": "daily_limit_reached", "message": "Quota used", "quota": {"left": 0}}, status=429,
                                headers={"Retry-After": "120", "X-RateLimit-Reason": "hash_lookup"})
        code, out, err, opener = self.invoke(["limits", "--format", "json"], response)
        self.assertEqual(code, 4)
        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(out, "")
        payload = json.loads(err)
        self.assertEqual(payload["quota"], {"left": 0})
        self.assertEqual(payload["retry_after"], "120")
        self.assertEqual(payload["rate_limit_reason"], "hash_lookup")

    def test_http_error_path_is_parsed(self):
        headers = HTTPMessage()
        headers["Content-Type"] = "application/json"
        error = HTTPError("https://example.invalid", 403, "Forbidden", headers, io.BytesIO(b'{"error":"enterprise_required","message":"Upgrade needed"}'))
        code, _, err, opener = self.invoke(["rules", "manifest", "--format", "json"], error=error)
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(err)["error"], "enterprise_required")
        self.assertEqual(len(opener.requests), 1)

    def test_no_redirects_and_merged_record_is_visible(self):
        self.assertIsNone(NoRedirects().redirect_request(None, None, 301, None, None, "https://elsewhere.example"))
        response = FakeResponse({"merged_into": "new-id"}, status=301, headers={"Location": "https://api.promptintel.securitybreak.io/api/v1/agent-threats/new-id"})
        code, _, err, opener = self.invoke(["threat", "get", "old-id", "--format", "json"], response)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["merged_into"], "new-id")
        self.assertEqual(len(opener.requests), 1)

    def test_html_and_invalid_json_are_actionable(self):
        for command in (["feed"], ["rules", "download"], ["export", "indicators"]):
            with self.subTest(command=command):
                code, out, err, _ = self.invoke(command + ["--format", "json"], FakeResponse(raw=b"<html>not API</html>", headers={"Content-Type": "text/html"}))
                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn("API", json.loads(err)["message"])

    def test_network_error_redaction_and_no_retry(self):
        code, out, err, opener = self.invoke(["feed", "--debug"], error=URLError("failure " + TEST_KEY))
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertNotIn(TEST_KEY, err)
        self.assertEqual(len(opener.requests), 1)

    def test_redacts_echoed_credentials_in_success_errors_and_metadata(self):
        for status in (200, 400):
            for format in ("json", "markdown", "text"):
                with self.subTest(status=status, format=format):
                    payload = {"message": "echo " + TEST_KEY, "data": ["ak_another_fake_credential"], "success": status == 200}
                    code, out, err, _ = self.invoke(["feed", "--format", format, "--debug"], FakeResponse(payload, status=status, headers={"ETag": TEST_KEY}))
                    self.assertEqual(code, 0 if status == 200 else 1)
                    self.assertNotIn(TEST_KEY, out + err)
                    self.assertNotIn("ak_another_fake_credential", out + err)
                    self.assertIn("[REDACTED]", out + err)

    def test_markdown_and_text_do_not_execute_control_or_render_attack_html(self):
        payload = {"text": "```\n<script>attack</script>\n\x1b[31m\u202eevil", "metadata": {"partial": True}}
        markdown = render(payload, "markdown")
        self.assertIn("````text", markdown)
        self.assertTrue(markdown.endswith("````\n"))
        self.assertNotIn("\x1b", markdown)
        self.assertNotIn("\u202e", markdown)
        self.assertEqual(json.loads(render(payload, "json")), payload)
        self.assertIn("metadata:", markdown)

    def test_body_keeps_null_fingerprint_and_new_fields_unchanged(self):
        body = {"severity": "critical", "description": None, "fingerprint": "test-id", "future_field": {"enabled": True}}
        code, _, err, opener = self.invoke(["reports", "edit", "id", "--data", "-", "--yes", "--debug"], stdin=json.dumps(body))
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(opener.requests[0][0].data), body)
        self.assertEqual(opener.requests[0][0].method, "PATCH")
        self.assertNotIn("future_field", err)

    def test_submissions_and_uploads_require_explicit_consent(self):
        for args in (["reports", "submit"], ["reports", "edit", "id"], ["submissions", "submit"], ["submissions", "edit", "id"], ["prompts", "submit"], ["rule-lab", "test"]):
            with self.subTest(args=args):
                code, _, err, opener = self.invoke([*args, "--data", "-", "--format", "json"], stdin="{}")
                self.assertEqual(code, 5, err)
                self.assertEqual(opener.requests, [])
                self.assertIn("--yes", json.loads(err)["message"])

    def test_json_validation_and_argument_error_format(self):
        for stdin in ("[]", "{invalid", '{"confidence": NaN}'):
            code, _, err, opener = self.invoke(["prompts", "search", "--data", "-", "--format", "json"], stdin=stdin)
            self.assertEqual(code, 2)
            self.assertEqual(opener.requests, [])
            self.assertIn("JSON", json.loads(err)["message"])
        code, _, err, opener = self.invoke(["prompts", "list", "--limit", "51", "--format", "json"])
        self.assertEqual(code, 2)
        self.assertIn("1..50", json.loads(err)["message"])

    def test_hash_lookup_only_sends_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_bytes(b"private content")
            code, _, err, opener = self.invoke(["artifacts", "lookup", "--file", str(path)])
        self.assertEqual(code, 0, err)
        request = opener.requests[0][0]
        self.assertEqual(parse_qs(urlsplit(request.full_url).query)["sha256"], [hashlib.sha256(b"private content").hexdigest()])
        self.assertIsNone(request.data)
        self.assertNotIn("private content", request.full_url)

    def test_scan_files_private_exact_selection_and_consent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SKILL.md").write_text("sample skill", encoding="utf-8")
            (root / ".env").write_text("unselected secret", encoding="utf-8")
            args = ["scan-files", "SKILL.md", "--root", directory, "--kind", "skill"]
            code, _, err, opener = self.invoke(args)
            self.assertEqual(code, 5, err)
            self.assertEqual(opener.requests, [])
            code, _, err, opener = self.invoke(args + ["--yes", "--static"])
            self.assertEqual(code, 0, err)
            body = json.loads(opener.requests[0][0].data)
            self.assertEqual(body["files"], [{"path": "SKILL.md", "content": "sample skill"}])
            self.assertTrue(body["private"])
            self.assertFalse(body["deep_review"])

    def test_local_scan_refuses_paths_symlinks_binaries_and_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "binary").write_bytes(b"hello\x00there")
            (root / "invalid-utf8").write_bytes(b"\xff")
            (root / "large").write_bytes(b"a" * (3 * 1024 * 1024 + 1))
            (root / "link").symlink_to(root / "binary")
            (root / "text").write_text("text")
            for filenames in (["../escape"], ["/absolute"], ["link"], ["binary"], ["invalid-utf8"], ["large"], [".git/config"], ["text", "./text"]):
                with self.subTest(filenames=filenames):
                    code, _, err, opener = self.invoke(["scan-files", *filenames, "--root", directory, "--kind", "skill", "--yes"])
                    self.assertEqual(code, 2, err)
                    self.assertEqual(opener.requests, [])

    def test_scan_source_file_needs_consent(self):
        code, _, err, opener = self.invoke(["scan", "--source-file", "-"], stdin='{"tools": []}')
        self.assertEqual(code, 5, err)
        self.assertEqual(opener.requests, [])

    def test_server_credentials_come_from_env_and_are_redacted(self):
        with patch.dict(os.environ, {"MCP_TEST_SECRET": "target-private-secret"}):
            code, out, err, opener = self.invoke(["scan", "https://mcp.example/endpoint", "--server-key-env", "MCP_TEST_SECRET", "--debug"], FakeResponse({"data": "target-private-secret"}))
        self.assertEqual(code, 0, err)
        body = json.loads(opener.requests[0][0].data)
        self.assertEqual(body["key"], "target-private-secret")
        self.assertTrue(body["private"])
        self.assertNotIn("target-private-secret", out + err)

    def test_rules_etag_304_and_saved_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            header_path = Path(directory) / "headers.json"
            code, out, err, opener = self.invoke(["rules", "manifest", "--etag", '"v1"', "--format", "json", "--headers-output", str(header_path)],
                                                FakeResponse(status=304, headers={"ETag": '"v1"', "Set-Cookie": "secret"}, raw=b""))
            self.assertEqual(code, 0, err)
            self.assertTrue(json.loads(out)["not_modified"])
            self.assertEqual(json.loads(header_path.read_text()), {"etag": '"v1"'})
            self.assertEqual(opener.requests[0][0].get_header("If-none-match"), '"v1"')

    def test_native_rule_download_checksum_and_atomic_output(self):
        raw = b"rule Example {\n}\r\n"
        digest = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "rules.nov"
            output.write_text("existing")
            args = ["rules", "download", "--raw", "-o", str(output)]
            code, _, err, _ = self.invoke(args + ["--sha256", "0" * 64], FakeResponse(raw=raw))
            self.assertEqual(code, 1, err)
            self.assertEqual(output.read_text(), "existing")
            code, _, err, _ = self.invoke(args, FakeResponse(raw=raw, headers={"X-PromptIntel-Pack-Sha256": digest}))
            self.assertEqual(code, 0, err)
            self.assertEqual(output.read_bytes(), raw)

    def test_csv_output_formats_and_native_bytes(self):
        raw = b'"type","value"\r\n"domain","example.com"\r\n'
        code, out, err, _ = self.invoke(["export", "indicators", "--format", "json"], FakeResponse(raw=raw))
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out), {"data": [{"type": "domain", "value": "example.com"}]})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "indicators.csv"
            code, _, err, _ = self.invoke(["export", "indicators", "--raw", "-o", str(path)], FakeResponse(raw=raw))
            self.assertEqual(code, 0, err)
            self.assertEqual(path.read_bytes(), raw)

    def test_native_credentials_are_not_written(self):
        code, out, err, _ = self.invoke(["rules", "download", "--raw"], FakeResponse(raw=TEST_KEY.encode()))
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertNotIn(TEST_KEY, err)

    def test_taxii_media_type_query_and_path_escaping(self):
        code, _, err, opener = self.invoke(["taxii", "objects", "agent-files", "--match-type", "indicator,report", "--next", "opaque+/="])
        self.assertEqual(code, 0, err)
        request = opener.requests[0][0]
        self.assertEqual(request.get_header("Accept"), "application/taxii+json;version=2.1")
        self.assertEqual(parse_qs(urlsplit(request.full_url).query), {"match[type]": ["indicator,report"], "next": ["opaque+/="]})
        code, _, err, opener = self.invoke(["threat", "get", "a/b?c"])
        self.assertEqual(code, 0, err)
        self.assertTrue(opener.requests[0][0].full_url.endswith("a%2Fb%3Fc"))

    def test_unsafe_base_urls_and_timeout_are_rejected(self):
        for url in ("http://remote.example/api", "https://user:secret@host.example/api", "https://host.example/api?key=x"):
            code, _, err, opener = self.invoke(["feed", "--api-url", url])
            self.assertEqual(code, 2, err)
            self.assertEqual(opener.requests, [])
        for timeout in ("0", "nan", "inf", "-1"):
            code, _, err, _ = self.invoke(["feed", "--timeout", timeout])
            self.assertEqual(code, 2, err)

    def test_all_declared_endpoints_have_usable_cli_routes(self):
        parser = build_parser()
        # Prepare each route without network traffic or external submissions.
        with tempfile.TemporaryDirectory() as directory:
            body = Path(directory) / "body.json"
            body.write_text("{}")
            sample = Path(directory) / "SKILL.md"
            sample.write_text("safe fixture")
            for endpoint in ENDPOINTS:
                args = endpoint.command.split()
                for name in re.findall(r"\{(\w+)\}", endpoint.path):
                    args.append("a" * 64 if name == "content_hash" else "test-id")
                if endpoint.body:
                    args.extend(["--data", str(body)])
                if endpoint.consent:
                    args.append("--yes")
                for query in endpoint.queries:
                    if query.required:
                        args.extend([query.flag or "--" + query.name.replace("_", "-"), "test-value"])
                if endpoint.command == "check":
                    args.append("example.com")
                elif endpoint.command == "scan":
                    args.append("https://example.com")
                elif endpoint.command == "scan-files":
                    args.extend(["SKILL.md", "--root", directory, "--kind", "skill"])
                elif endpoint.command == "artifacts lookup":
                    args.append("a" * 64)
                with self.subTest(endpoint=endpoint.command):
                    parsed = parser.parse_args(args)
                    method, path, _, _ = prepare_request(parsed, Client())
                    self.assertEqual(method, endpoint.method)
                    self.assertNotIn("{", path)
                    self.assertEqual(parsed.endpoint, endpoint)

    def test_incomplete_http_response_becomes_a_normal_error(self):
        code, out, err, opener = self.invoke(["feed", "--format", "json"], error=IncompleteRead(b"partial", 10))
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("Network request failed", json.loads(err)["message"])
        self.assertEqual(len(opener.requests), 1)


if __name__ == "__main__":
    unittest.main()
