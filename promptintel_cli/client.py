"""Small standard-library HTTP client with no redirects or automatic retries."""

from dataclasses import dataclass
import hashlib
from http.client import HTTPException
import ipaddress
import json
import math
import os
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from . import __version__

API_URL = "https://api.promptintel.securitybreak.io/api/v1"
SCANNER_URL = "https://promptintel.securitybreak.io/scanner-api/v1"
MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class ClientError(Exception):
    def __init__(self, message, *, code=1, payload=None):
        super().__init__(message)
        self.code = code
        self.payload = payload or {"error": "client_error", "message": message}


class Redactor:
    """Remove the active credentials even if a remote error echoes them back."""

    def __init__(self, *secrets):
        self.secrets = [secret for secret in secrets if secret]

    def add(self, secret):
        if secret:
            self.secrets.append(secret)

    def text(self, text):
        for secret in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(secret, "[REDACTED]")
        text = re.sub(r"\bak_[A-Za-z0-9_-]+", "[REDACTED]", text)
        return text

    def value(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.value(item) for item in value]
        if isinstance(value, dict):
            return {self.text(str(key)): self.value(item) for key, item in value.items()}
        return value


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward credentials or replay a submission at a redirect target.
        return None


@dataclass
class Response:
    payload: object
    raw: bytes
    headers: dict[str, str]
    status: int
    native: str


def validate_base_url(url):
    try:
        parts = urlsplit(url)
        host = parts.hostname
        _ = parts.port
    except ValueError as exc:
        raise ClientError("Invalid API base URL", code=2) from exc
    if not host or parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise ClientError("Base URLs must have a host and no credentials, query, or fragment", code=2)
    loopback = host == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if parts.scheme != "https" and not (parts.scheme == "http" and loopback):
        raise ClientError("Base URLs require HTTPS (HTTP is allowed only on loopback for tests)", code=2)
    if any(ord(char) < 33 for char in url):
        raise ClientError("Base URLs cannot contain whitespace or control characters", code=2)
    return url.rstrip("/")


class Client:
    def __init__(self, *, api_url=None, scanner_url=None, timeout=150, verbose=False, debug=False, stderr=None, profile=None):
        from .credentials import validate_profile

        if not math.isfinite(timeout) or timeout <= 0:
            raise ClientError("Timeout must be a finite positive number", code=2)
        self.bases = {
            "api": validate_base_url(api_url or os.environ.get("PROMPTINTEL_API_URL") or API_URL),
            "scanner": validate_base_url(scanner_url or os.environ.get("PROMPTINTEL_SCANNER_URL") or SCANNER_URL),
        }
        self.key = os.environ.get("PROMPTINTEL_API_KEY", "").strip()
        self.profile = validate_profile(profile) if profile is not None else None
        self.credential_source = "environment" if self.key else "keyring" if self.profile else "none"
        self.credential_backend = None
        self._credential_error = None
        self._credentials_loaded = bool(self.key) or self.profile is None
        self.redactor = Redactor(self.key)
        self.timeout = timeout
        self.verbose = verbose or debug
        self.debug = debug
        self.stderr = stderr if stderr is not None else sys.stderr
        self.opener = build_opener(NoRedirects())

    def load_credentials(self):
        """Resolve only when needed; public commands never unlock a keyring."""
        if self._credential_error is not None:
            raise self._credential_error
        if not self._credentials_loaded:
            from .credentials import CredentialStore

            try:
                store = CredentialStore()
                self.credential_backend = store.name
                self.key = store.get(self.profile) or ""
                self.redactor.add(self.key)
                if not self.key:
                    raise ClientError("No key is stored for the selected profile. Run auth set --profile NAME or set PROMPTINTEL_API_KEY", code=3)
            except ClientError as exc:
                self._credential_error = exc
                raise
            self._credentials_loaded = True

    def require_credentials(self):
        self.load_credentials()
        if not self.key:
            raise ClientError("Set PROMPTINTEL_API_KEY in your environment or select a stored key with --profile NAME", code=3)
        if not self.key.isascii() or any(ord(char) < 33 or ord(char) == 127 for char in self.key):
            raise ClientError("The API credential contains invalid header characters", code=3)

    def log(self, message, *, debug=False):
        if (debug and self.debug) or (not debug and self.verbose):
            # JSON string escaping also stops terminal control sequences in metadata.
            safe = json.dumps(self.redactor.text(message), ensure_ascii=True)[1:-1]
            print(f"{'DEBUG' if debug else 'INFO'} {safe}", file=self.stderr)

    def request(self, method, path, *, service="api", params=(), body=None,
                auth=True, native="json", etag=None, label=None):
        if service not in self.bases:
            raise ClientError("Unknown API service", code=2)
        if not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path:
            raise ClientError("Use an API path and separate query parameters", code=2)
        if auth:
            self.require_credentials()
        headers = {"Accept": "application/json", "User-Agent": f"promptintel-cli/{__version__}"}
        if path.startswith("/taxii2/"):
            headers["Accept"] = "application/taxii+json;version=2.1"
        elif native == "text":
            headers["Accept"] = "text/plain"
        elif native == "csv":
            headers["Accept"] = "text/csv"
        if auth:
            headers["Authorization"] = f"Bearer {self.key}"
        if etag:
            if not etag.isascii() or any(ord(char) < 32 or ord(char) == 127 for char in etag):
                raise ClientError("ETag contains invalid header characters", code=2)
            headers["If-None-Match"] = etag
        encoded = None
        if body is not None:
            try:
                encoded = json.dumps(body, ensure_ascii=True, allow_nan=False).encode("utf-8")
            except (TypeError, ValueError) as exc:
                raise ClientError("Request body must be valid JSON", code=2) from exc
            headers["Content-Type"] = "application/json"
        query = urlencode(params, doseq=True)
        url = self.bases[service] + path + ("?" + query if query else "")
        request = Request(url, data=encoded, headers=headers, method=method)
        # Log the command label, never a URL/query, headers, or body with user data.
        self.log(f"{method} {service}: {label or 'request'}")
        self.log(f"timeout={self.timeout:g}s request_bytes={len(encoded or b'')} auth={'bearer' if auth else 'none'}", debug=True)
        started = time.monotonic()
        try:
            try:
                handle = self.opener.open(request, timeout=self.timeout)
            except HTTPError as exc:
                handle = exc
            with handle:
                status = handle.code
                response_headers = {key.lower(): value for key, value in handle.headers.items()}
                raw = handle.read(MAX_RESPONSE_BYTES + 1)
        except (URLError, OSError, HTTPException, ValueError) as exc:
            raise ClientError("Network request failed: " + self.redactor.text(str(exc))) from exc
        self.log(f"HTTP {status} in {time.monotonic() - started:.2f}s ({len(raw)} bytes)")
        for name in ("content-type", "etag", "retry-after", "x-ratelimit-reason", "x-taxii-date-added-last", "x-promptintel-pack-sha256"):
            if name in response_headers:
                self.log(f"{name}: {response_headers[name]}", debug=True)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ClientError("Response exceeds the 64 MiB client limit")
        if status == 304:
            return Response({"not_modified": True, "etag": response_headers.get("etag", etag)}, b"", response_headers, status, "json")
        try:
            decoded = raw.decode("utf-8-sig")
        except UnicodeError as exc:
            raise ClientError("API response is not UTF-8 text") from exc
        try:
            payload = json.loads(decoded)
            parsed_json = True
        except ValueError:
            payload = None
            parsed_json = False
        if not 200 <= status < 300:
            error = dict(payload) if isinstance(payload, dict) else {"error": "http_error"}
            error["http_status"] = status
            if not error.get("message"):
                error["message"] = f"PromptIntel returned HTTP {status}"
            if status in (301, 302, 303, 307, 308):
                error["location"] = response_headers.get("location")
                error["hint"] = "Redirect not followed. For merged records, request the returned merged_into ID."
            if not parsed_json:
                error["hint"] = "Non-JSON response. Check the API base URL and any proxy; the website is not the API."
            if status == 429:
                reason = response_headers.get("x-ratelimit-reason", "unspecified")
                retry = response_headers.get("retry-after")
                error["rate_limit_reason"] = reason
                if retry:
                    error["retry_after"] = retry
                    error["hint"] = f"Wait for Retry-After ({retry}) before retrying. No retry was attempted."
                elif reason == "minute":
                    error["hint"] = "Wait at least 60 seconds before retrying. No retry was attempted."
                elif reason == "submission_quota":
                    error["hint"] = "Wait until the rolling 24-hour quota frees a slot; inspect quota in the response."
                elif reason in ("day", "prompt_read", "threat_detail", "hash_lookup"):
                    error["hint"] = "Wait until 00:00 UTC before retrying. No retry was attempted."
                else:
                    error["hint"] = "Wait before retrying; inspect the response or limits/quota command. No retry was attempted."
            error = self.redactor.value(error)
            raise ClientError(str(error["message"]), code=4 if status == 429 else 3 if status in (401, 403) else 1, payload=error)
        if isinstance(payload, dict) and (payload.get("success") is False or payload.get("error")):
            error = self.redactor.value(payload)
            raise ClientError(str(error.get("message", error.get("error", "API reported a failure"))), payload=error)
        if native == "json" and not parsed_json and status != 204:
            raise ClientError("Expected JSON but received another format. Check the API base URL (not the website) and proxy.")
        if native != "json":
            if "text/html" in response_headers.get("content-type", "").lower() or decoded.lstrip().lower().startswith(("<!doctype html", "<html")):
                raise ClientError("Received HTML instead of the requested download. Check the API base URL and proxy.")
            payload = decoded
        return Response(self.redactor.value(payload), raw, response_headers, status, native)


def verify_sha256(response, expected=None):
    """Verify a native rule download before writing it. Hash the original bytes."""
    advertised = response.headers.get("x-promptintel-pack-sha256")
    for value in (expected, advertised):
        if value is None:
            continue
        value = value.removeprefix("sha256:").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ClientError("Rule pack checksum must be a 64-character SHA-256", code=2)
        if hashlib.sha256(response.raw).hexdigest() != value:
            raise ClientError("Rule pack SHA-256 mismatch; the download was not written")
    return bool(expected or advertised)
