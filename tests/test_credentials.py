"""Credential workflows use an in-memory stand-in, never the user's keychain."""

import contextlib
import getpass
import importlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import warnings

from promptintel_cli.cli import main
from promptintel_cli.client import Client, ClientError
from promptintel_cli.credentials import CredentialStore, SERVICE, validate_profile
from scripts import test_live
from tests.test_cli import FakeResponse
from tests.test_live_runner import FakeCLI, KEYS
from tests.test_workflows import SequenceOpener

STORED_KEY = "ak_test_stored_credential_123456"
ENV_KEY = "ak_test_environment_credential_7890"


class MemoryStore:
    def __init__(self, values=None, error=None):
        self.values = dict(values or {})
        self.error = error
        self.calls = []

    def get_password(self, service, profile):
        self.calls.append(("get", service, profile))
        if self.error:
            raise self.error
        return self.values.get((service, profile))

    def set_password(self, service, profile, key):
        self.calls.append(("set", service, profile))
        if self.error:
            raise self.error
        self.values[service, profile] = key

    def delete_password(self, service, profile):
        self.calls.append(("delete", service, profile))
        if self.error:
            raise self.error
        del self.values[service, profile]


NativeStore = type("Keyring", (MemoryStore,), {"__module__": "keyring.backends.macOS"})
PlaintextStore = type("PlaintextKeyring", (MemoryStore,), {"__module__": "keyrings.alt.file"})
NullStore = type("Keyring", (MemoryStore,), {"__module__": "keyring.backends.null"})


class TTY(io.StringIO):
    def isatty(self):
        return True


class CredentialTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.backend = NativeStore({(SERVICE, "enterprise"): STORED_KEY})
        self.keyring = SimpleNamespace(get_keyring=lambda: self.backend)
        modules = patch.dict(sys.modules, {"keyring": self.keyring})
        modules.start()
        self.addCleanup(modules.stop)

    def invoke(self, argv, responses=(), *, terminal=False):
        out, err = io.StringIO(), io.StringIO()
        opener = SequenceOpener(responses)
        with patch("promptintel_cli.client.build_opener", return_value=opener), \
                patch("sys.stdin", TTY() if terminal else io.StringIO()), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*argv, "--format", "json"])
        for secret in (STORED_KEY, ENV_KEY):
            self.assertNotIn(secret, out.getvalue() + err.getvalue())
        return code, out.getvalue(), err.getvalue(), opener.requests

    def test_stored_profile_authenticates_both_services_and_redacts_echoes(self):
        for command in (["feed"], ["quota"]):
            with self.subTest(command=command):
                response = FakeResponse({"data": {"echo": STORED_KEY}}, headers={"ETag": STORED_KEY})
                code, out, err, requests = self.invoke([*command, "--profile", "enterprise", "--debug"], [response])
                self.assertEqual(code, 0, err)
                self.assertEqual(requests[0].get_header("Authorization"), "Bearer " + STORED_KEY)
                self.assertEqual(json.loads(out)["data"]["echo"], "[REDACTED]")
        self.assertEqual(self.backend.calls, [("get", SERVICE, "enterprise")] * 2)

    def test_environment_override_never_opens_keyring(self):
        self.keyring.get_keyring = lambda: self.fail("Environment auth must not open keyring")
        with patch.dict(os.environ, {"PROMPTINTEL_API_KEY": ENV_KEY}):
            code, _, err, requests = self.invoke(["--profile", "enterprise", "feed", "--verbose"], [FakeResponse()])
        self.assertEqual(code, 0, err)
        self.assertEqual(requests[0].get_header("Authorization"), "Bearer " + ENV_KEY)
        self.assertIn("overridden", err)

    def test_no_profile_preserves_environment_only_behavior(self):
        self.keyring.get_keyring = lambda: self.fail("No profile selected")
        code, out, _, requests = self.invoke(["feed"])
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertEqual(requests, [])

    def test_public_and_local_commands_never_open_keyring(self):
        self.keyring.get_keyring = lambda: self.fail("Public or local command opened keyring")
        for command in ("health", "keys", "endpoints"):
            with self.subTest(command=command):
                code, _, err, requests = self.invoke([command, "--profile", "enterprise"], [FakeResponse()])
                self.assertEqual(code, 0, err)
                if requests:
                    self.assertIsNone(requests[0].get_header("Authorization"))

    def test_missing_extra_is_actionable_without_breaking_environment_auth(self):
        original_import = importlib.import_module

        def without_keyring(name, *args, **kwargs):
            if name == "keyring":
                raise ModuleNotFoundError("secret-bearing import failure " + STORED_KEY)
            return original_import(name, *args, **kwargs)

        with patch("promptintel_cli.credentials.importlib.import_module", side_effect=without_keyring):
            code, _, err, requests = self.invoke(["feed", "--profile", "enterprise"])
            self.assertEqual(code, 2)
            self.assertIn("promptintel-cli[keyring]", json.loads(err)["message"])
            self.assertEqual(requests, [])
            with patch.dict(os.environ, {"PROMPTINTEL_API_KEY": ENV_KEY}):
                code, _, err, _ = self.invoke(["feed", "--profile", "enterprise"], [FakeResponse()])
                self.assertEqual(code, 0, err)

    def test_missing_or_malformed_stored_profile_is_auth_error(self):
        for value in (None, "", "invalid", "ak_short", "ak_invalid\nheader"):
            with self.subTest(value=value):
                self.backend.values[SERVICE, "broken"] = value
                code, out, _, requests = self.invoke(["feed", "--profile", "broken"])
                self.assertEqual(code, 3)
                self.assertEqual(out, "")
                self.assertEqual(requests, [])

    def test_profile_names_are_validated_before_store_access(self):
        for profile in ("", "../escape", "my key", "-leading", "a" * 65, STORED_KEY):
            with self.subTest(length=len(profile)):
                code, _, _, requests = self.invoke(["feed", "--profile", profile])
                self.assertEqual(code, 2)
                self.assertEqual(requests, [])
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(validate_profile("team.enterprise-2"), "team.enterprise-2")

    def test_set_uses_hidden_input_and_verifies_the_saved_key(self):
        with patch("promptintel_cli.credentials.getpass.getpass", return_value=STORED_KEY) as prompt:
            code, out, err, requests = self.invoke(["auth", "set", "--profile", "community"], terminal=True)
        self.assertEqual(code, 0, err)
        self.assertEqual(requests, [])
        prompt.assert_called_once()
        self.assertEqual(self.backend.values[SERVICE, "community"], STORED_KEY)
        self.assertEqual(self.backend.calls, [("set", SERVICE, "community"), ("get", SERVICE, "community")])
        self.assertEqual(json.loads(out)["status"], "saved")

    def test_set_and_delete_target_profile_even_when_environment_is_set(self):
        with patch.dict(os.environ, {"PROMPTINTEL_API_KEY": ENV_KEY}), \
                patch("promptintel_cli.credentials.getpass.getpass", return_value=STORED_KEY):
            code, out, err, _ = self.invoke(["--profile", "personal", "auth", "set"], terminal=True)
            self.assertEqual(code, 0, err)
            self.assertTrue(json.loads(out)["environment_override"])
            self.assertEqual(self.backend.values[SERVICE, "personal"], STORED_KEY)
            code, out, err, _ = self.invoke(["auth", "--profile", "personal", "delete"])
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(out)["status"], "deleted")
            self.assertEqual(os.environ["PROMPTINTEL_API_KEY"], ENV_KEY)
        self.assertNotIn((SERVICE, "personal"), self.backend.values)

    def test_status_reports_presence_without_returning_secret_or_using_http(self):
        for profile, expected in (("enterprise", 0), ("missing", 3)):
            code, out, err, requests = self.invoke(["auth", "status", "--profile", profile])
            self.assertEqual(code, expected, err)
            report = json.loads(out)
            self.assertEqual(set(report), {"profile", "service", "backend", "status", "environment_override"})
            self.assertEqual(requests, [])

    def test_auth_default_profile_and_missing_delete(self):
        with patch("promptintel_cli.credentials.getpass.getpass", return_value=STORED_KEY):
            code, out, err, _ = self.invoke(["auth", "set"], terminal=True)
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(out)["profile"], "default")
        code, _, _, _ = self.invoke(["auth", "delete", "--profile", "absent"])
        self.assertEqual(code, 3)

    def test_noninteractive_or_echoing_input_is_refused_before_saving(self):
        with patch("promptintel_cli.credentials.getpass.getpass") as prompt:
            code, _, _, _ = self.invoke(["auth", "set", "--profile", "new"])
            self.assertEqual(code, 2)
            prompt.assert_not_called()

        def echo_fallback(*args, **kwargs):
            warnings.warn("Cannot control echo", getpass.GetPassWarning)
            self.fail("The echoing fallback must not read input")

        for failure in (EOFError(), OSError(STORED_KEY), echo_fallback):
            with patch("promptintel_cli.credentials.getpass.getpass", side_effect=failure):
                code, _, _, _ = self.invoke(["auth", "set", "--profile", "new"], terminal=True)
                self.assertEqual(code, 2)
        self.assertEqual(self.backend.calls, [])

    def test_invalid_or_interrupted_key_entry_never_saves(self):
        for value in ("", "bad", "ak_invalid\r\nheader"):
            with patch("promptintel_cli.credentials.getpass.getpass", return_value=value):
                code, _, _, _ = self.invoke(["auth", "set"], terminal=True)
                self.assertEqual(code, 2)
        with patch("promptintel_cli.credentials.getpass.getpass", side_effect=KeyboardInterrupt):
            code, _, _, _ = self.invoke(["auth", "set"], terminal=True)
            self.assertEqual(code, 130)
        self.assertEqual(self.backend.calls, [])

    def test_store_failures_do_not_print_backend_exception_text(self):
        self.backend.error = RuntimeError("PRIVATE-BACKEND-DETAIL " + STORED_KEY)
        for command in (["auth", "set"], ["auth", "status"], ["auth", "delete"], ["feed"]):
            with patch("promptintel_cli.credentials.getpass.getpass", return_value=STORED_KEY):
                code, out, err, requests = self.invoke([*command, "--profile", "enterprise", "--debug"], terminal=True)
                self.assertEqual(code, 3)
                self.assertNotIn("PRIVATE-BACKEND-DETAIL", out + err)
                self.assertEqual(requests, [])

    def test_set_does_not_report_success_when_backend_silently_fails(self):
        with patch.object(self.backend, "set_password"), patch("promptintel_cli.credentials.getpass.getpass", return_value=STORED_KEY):
            code, out, _, _ = self.invoke(["auth", "set", "--profile", "new"], terminal=True)
            self.assertEqual(code, 3)
            self.assertEqual(out, "")

    def test_delete_does_not_report_success_when_backend_silently_fails(self):
        with patch.object(self.backend, "delete_password"):
            code, out, _, _ = self.invoke(["auth", "delete", "--profile", "enterprise"])
            self.assertEqual(code, 3)
            self.assertEqual(out, "")

    def test_plaintext_null_and_unknown_backends_are_never_used(self):
        for backend in (PlaintextStore(), NullStore(), MemoryStore()):
            with self.subTest(backend=type(backend).__name__):
                self.keyring.get_keyring = lambda: backend
                with patch("promptintel_cli.credentials.getpass.getpass") as prompt:
                    code, _, _, _ = self.invoke(["auth", "set"], terminal=True)
                    self.assertEqual(code, 3)
                    prompt.assert_not_called()
                self.assertEqual(backend.calls, [])

    def test_chainer_selects_one_native_store_and_never_falls_back(self):
        plain = PlaintextStore({(SERVICE, "enterprise"): ENV_KEY})
        chain_type = type("ChainerBackend", (), {"__module__": "keyring.backends.chainer"})
        chain = chain_type()
        chain.backends = [plain, self.backend]
        self.keyring.get_keyring = lambda: chain
        self.assertEqual(CredentialStore().get("enterprise"), STORED_KEY)
        self.backend.error = RuntimeError("locked")
        with self.assertRaises(ClientError):
            CredentialStore().get("enterprise")
        self.assertEqual(plain.calls, [])
        chain.backends = [plain]
        with self.assertRaises(ClientError):
            CredentialStore()

    def test_client_resolves_once_and_registers_stored_key_for_redaction(self):
        opener = SequenceOpener([FakeResponse(), FakeResponse()])
        with patch("promptintel_cli.client.build_opener", return_value=opener):
            client = Client(profile="enterprise")
            self.assertEqual(self.backend.calls, [])
            client.request("GET", "/health", auth=False)
            self.assertEqual(self.backend.calls, [])
            client.request("GET", "/agent-feed")
            client.require_credentials()
        self.assertEqual(self.backend.calls, [("get", SERVICE, "enterprise")])
        self.assertEqual(client.redactor.text(STORED_KEY), "[REDACTED]")

    def test_doctor_identifies_effective_source_plan_and_profile(self):
        for environment in ({}, {"PROMPTINTEL_API_KEY": ENV_KEY}):
            with self.subTest(environment=bool(environment)), patch.dict(os.environ, environment, clear=True):
                responses = [FakeResponse({"data": {"status": "ok"}}),
                             FakeResponse({"data": {"plan": "enterprise"}}), FakeResponse({"data": {"scans": {}}})]
                code, out, err, _ = self.invoke(["doctor", "--profile", "enterprise"], responses)
                self.assertEqual(code, 0, err)
                report = json.loads(out)
                self.assertEqual(report["credential_source"], "environment" if environment else "keyring")
                self.assertEqual(report["requested_profile"], "enterprise")
                self.assertEqual(report["credential_profile"], None if environment else "enterprise")
                self.assertEqual(report["credential_backend"], None if environment else "macOS Keychain")
                self.assertEqual(report["checks"][1]["response"]["data"]["plan"], "enterprise")

    def test_doctor_keeps_health_result_when_keyring_is_locked_and_does_not_reprompt(self):
        self.backend.error = RuntimeError("locked " + STORED_KEY)
        code, out, err, requests = self.invoke(["doctor", "--profile", "enterprise"], [FakeResponse({"data": {"status": "ok"}})])
        self.assertEqual(code, 3, err)
        self.assertEqual([row["status"] for row in json.loads(out)["checks"]], ["ok", "error", "error"])
        self.assertEqual(len(requests), 1)
        self.assertEqual(self.backend.calls, [("get", SERVICE, "enterprise")])

    def test_auth_cannot_accept_raw_key_argument_or_http_header_output(self):
        for args in (["auth", "set", STORED_KEY], ["auth", "status", "--headers-output", "headers.json"]):
            code, _, _, requests = self.invoke(args, terminal=True)
            self.assertEqual(code, 2)
            self.assertEqual(requests, [])
        self.assertEqual(self.backend.calls, [])

    def test_live_runner_loads_both_profiles_without_reading_a_file(self):
        self.backend.values = {(SERVICE, "test-community"): KEYS["community"], (SERVICE, "test-enterprise"): KEYS["enterprise"]}
        with patch.dict(os.environ, {"PROMPTINTEL_API_KEY": ENV_KEY}):
            self.assertEqual(test_live.load_keyring_keys("test-community", "test-enterprise"), KEYS)
        for community, enterprise in (("absent", "test-enterprise"), ("test-community", "test-community")):
            with self.assertRaises(test_live.ConfigurationError):
                test_live.load_keyring_keys(community, enterprise)

    def test_live_keyring_mode_keeps_reports_sanitized_and_existing_matrix(self):
        self.backend.values = {(SERVICE, plan): key for plan, key in KEYS.items()}
        fake = FakeCLI()
        real_runner = test_live.LiveRunner

        def runner(keys, **kwargs):
            return real_runner(keys, **kwargs, execute=fake, sleep=lambda _: None)

        with tempfile.TemporaryDirectory() as directory, patch.object(test_live, "LiveRunner", side_effect=runner), \
                patch.object(test_live, "load_keys", side_effect=AssertionError("Keyring mode must not read a key file")):
            report_path = Path(directory) / "report.json"
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = test_live.main(["--keyring", "--cases", "limits", "--report", str(report_path)])
            self.assertEqual(code, 0, err.getvalue())
            report = json.loads(report_path.read_text())
            self.assertEqual(report["summary"]["pass"], 2)
            for key in KEYS.values():
                self.assertNotIn(key, out.getvalue() + err.getvalue() + report_path.read_text())
        self.assertEqual([(plan, case) for plan, case, _, _ in fake.calls], [("community", "limits"), ("enterprise", "limits")])

    def test_live_profile_flags_require_keyring_mode_and_backend_errors_are_safe(self):
        self.backend.error = RuntimeError("PRIVATE-BACKEND-DETAIL " + STORED_KEY)
        for options in (["--community-profile", "community"], ["--keyring"]):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = test_live.main(options)
            self.assertEqual(code, 2)
            self.assertNotIn(STORED_KEY, err.getvalue())
            self.assertNotIn("PRIVATE-BACKEND-DETAIL", err.getvalue())
