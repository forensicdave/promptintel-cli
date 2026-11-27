"""Optional OS credential storage. Never fall back to a file-based backend."""

import getpass
import importlib
import os
import re
import sys
import warnings

from .client import ClientError

SERVICE = "promptintel-cli"
PROFILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
KEY = re.compile(r"ak_[A-Za-z0-9_-]{8,}\Z")
NATIVE_BACKENDS = {
    ("keyring.backends.macOS", "Keyring"): "macOS Keychain",
    ("keyring.backends.SecretService", "Keyring"): "Secret Service",
    ("keyring.backends.libsecret", "Keyring"): "libsecret",
    ("keyring.backends.kwallet", "DBusKeyring"): "KWallet",
    ("keyring.backends.kwallet", "DBusKeyringKWallet4"): "KWallet 4",
}


def validate_profile(profile):
    if not isinstance(profile, str) or not PROFILE.fullmatch(profile) or profile.startswith("ak_"):
        raise ClientError("Profile names must be 1-64 letters, digits, dots, underscores or hyphens, start with a letter/digit, and must not be API keys", code=2)
    return profile


def validate_key(value):
    if not isinstance(value, str) or not KEY.fullmatch(value.strip()):
        raise ClientError("Expected a nonempty PromptIntel ak_ credential; the value was not saved or sent", code=2)
    return value.strip()


def backend_type(backend):
    return type(backend).__module__, type(backend).__name__


class CredentialStore:
    def __init__(self):
        try:
            keyring = importlib.import_module("keyring")
        except ImportError:
            raise ClientError("Keyring support is not installed in this Python environment. Install 'promptintel-cli[keyring]' or use PROMPTINTEL_API_KEY", code=2) from None
        except Exception:
            raise ClientError("Keyring could not be imported. Check the optional keyring installation", code=2) from None
        try:
            selected = keyring.get_keyring()
            if backend_type(selected) == ("keyring.backends.chainer", "ChainerBackend"):
                # Select one native backend. Do not call the chain, which might
                # read/write plaintext or silently try a different credential store.
                selected = next((item for item in selected.backends if backend_type(item) in NATIVE_BACKENDS), None)
            if backend_type(selected) not in NATIVE_BACKENDS:
                raise ClientError("No supported OS credential store is available. Configure macOS Keychain, Secret Service or KWallet; file, null and unknown backends are refused", code=3)
            self.backend = selected
            self.name = NATIVE_BACKENDS[backend_type(selected)]
        except ClientError:
            raise
        except Exception:
            raise ClientError("Cannot initialize the OS credential store. Check its installation, session and unlock state", code=3) from None

    def get(self, profile):
        validate_profile(profile)
        try:
            value = self.backend.get_password(SERVICE, profile)
        except Exception:
            # Backend errors may contain credentials. Never forward their text.
            raise ClientError("Cannot read the OS credential store. Unlock it and allow access, then try again", code=3) from None
        if value is None:
            return None
        try:
            return validate_key(value)
        except ClientError:
            raise ClientError("The stored profile does not contain a valid-looking PromptIntel key. Replace it with auth set", code=3) from None

    def set(self, profile, key):
        validate_profile(profile)
        key = validate_key(key)
        try:
            self.backend.set_password(SERVICE, profile, key)
        except Exception:
            raise ClientError("Cannot save the key in the OS credential store. Unlock it and allow access, then try again", code=3) from None

    def delete(self, profile):
        validate_profile(profile)
        try:
            self.backend.delete_password(SERVICE, profile)
        except Exception:
            raise ClientError("Cannot delete the stored profile. Check that it exists and the OS credential store is unlocked", code=3) from None


def manage_credentials(action, profile, redactor):
    profile = validate_profile(profile)
    # Refuse noninteractive input and getpass's echoing fallback. Never accept
    # the key as an argument, ordinary stdin, or an implicit environment import.
    if action == "set" and not sys.stdin.isatty():
        raise ClientError("auth set requires an interactive terminal for hidden input. Use PROMPTINTEL_API_KEY for automation", code=2)
    store = CredentialStore()
    if action == "set":
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                key = getpass.getpass("PromptIntel API key (hidden): ", stream=sys.stderr)
        except (getpass.GetPassWarning, EOFError, OSError):
            raise ClientError("Cannot read a key with hidden input; nothing was saved", code=2) from None
        redactor.add(key)
        key = validate_key(key)
        redactor.add(key)
        store.set(profile, key)
        # Some backends do not report failed writes. Confirm before reporting success.
        if store.get(profile) != key:
            raise ClientError("The saved key could not be verified. Check the OS credential store before using this profile", code=3)
        status, code = "saved", 0
    elif action == "delete":
        store.delete(profile)
        if store.get(profile) is not None:
            raise ClientError("The profile is still present after deletion. Check the OS credential store", code=3)
        status, code = "deleted", 0
    else:
        stored = store.get(profile)
        status, code = ("present", 0) if stored else ("missing", 3)
    return {"profile": profile, "service": SERVICE, "backend": store.name, "status": status,
            "environment_override": bool(os.environ.get("PROMPTINTEL_API_KEY", "").strip())}, code
