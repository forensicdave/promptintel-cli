"""Read-only connectivity, authentication, plan and quota diagnostics."""

import platform

from . import __version__
from .client import ClientError


def doctor(client):
    checks = []
    headers = {}
    codes = []
    stopped = False
    operations = (
        ("api_health", "api", "/health", False),
        ("account", "api", "/agents/me/limits", True),
        ("scanner_quota", "scanner", "/quota", True),
    )
    for name, service, path, auth in operations:
        if stopped:
            checks.append({"name": name, "status": "skipped", "reason": "rate_limited"})
            continue
        if auth and not client.key and client.profile is None:
            checks.append({"name": name, "status": "skipped", "reason": "missing_api_key"})
            codes.append(3)
            continue
        try:
            response = client.request("GET", path, service=service, auth=auth, label="doctor " + name)
            data = response.payload.get("data", response.payload) if isinstance(response.payload, dict) else None
            if not isinstance(data, dict):
                raise ClientError("Expected an object in the diagnostic API response")
            if name == "account" and not isinstance(data.get("plan"), str):
                raise ClientError("Account response does not identify its plan")
            checks.append({"name": name, "status": "ok", "http_status": response.status, "response": response.payload})
            headers[name] = response.headers
        except ClientError as exc:
            checks.append({"name": name, "status": "error", "error": exc.payload, "exit_code": exc.code})
            codes.append(exc.code)
            stopped = exc.code == 4
    # Rate limits take priority, then missing/invalid credentials, then other errors.
    code = 4 if 4 in codes else 3 if 3 in codes else codes[0] if codes else 0
    payload = {"tool": "promptintel-cli", "version": __version__, "python": platform.python_version(),
               "platform": platform.system(), "api_key_configured": bool(client.key),
               "credential_source": client.credential_source, "requested_profile": client.profile,
               "credential_profile": client.profile if client.credential_source == "keyring" else None,
               "credential_backend": client.credential_backend,
               "ok": code == 0, "checks": checks}
    return client.redactor.value(payload), code, headers
