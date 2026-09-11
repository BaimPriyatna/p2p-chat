"""core/identity/key_storage.py — KeyStore: where the private key actually lives.

Implements IMPLEMENTATION_PLAN.md Phase 3.3's KeyStore abstraction.

Preference order:
    1. OS-native secure storage via `keyring`:
       Linux -> Secret Service, Windows -> Credential Manager (DPAPI),
       macOS -> Keychain. The private key never touches disk as plaintext.
    2. Fallback: a plaintext file with 0600 permissions (owner read/write
       only), used when no keyring backend is available — headless Linux
       without a Secret Service daemon, containers, CI, etc. This is
       strictly worse than (1) but still meaningfully better than the
       previous state (no protection at all on a random UUID that carried
       no secret to protect in the first place).

Callers can check `KeyStore.backend_name` to know (and, if useful, surface
to the user) which one is actually in effect.
"""

import os

import keyring
import keyring.errors

SERVICE_NAME = "peerc-device-identity"
DEFAULT_PLAINTEXT_PATH = os.path.expanduser("~/.peerc/device_key.pem")


class KeyStoreError(Exception):
    """Raised when a private key can be neither saved nor loaded."""


class KeyStore:
    def __init__(self, plaintext_fallback_path: str = DEFAULT_PLAINTEXT_PATH):
        self.plaintext_fallback_path = plaintext_fallback_path
        self.backend_name = "keyring" if self._keyring_usable() else "plaintext-file"

    def _keyring_usable(self) -> bool:
        """keyring always returns *some* backend object even when nothing
        real is configured — keyring.backends.fail.Keyring, whose
        get/set_password calls raise NoKeyringError. Detect that case up
        front rather than discovering it on the first real save/load."""
        try:
            backend = keyring.get_keyring()
        except Exception:
            return False
        return backend.__class__.__module__ != "keyring.backends.fail"

    def save_private_key(self, username: str, key_pem: str) -> str:
        """Persist a private key. Returns the backend actually used
        ("keyring" or "plaintext-file"), which may differ from
        self.backend_name if keyring raised at the last moment."""
        if self.backend_name == "keyring":
            try:
                keyring.set_password(SERVICE_NAME, username, key_pem)
                return "keyring"
            except keyring.errors.KeyringError:
                pass  # fall through to plaintext
        self._save_plaintext(key_pem)
        return "plaintext-file"

    def load_private_key(self, username: str) -> str | None:
        """Return the stored PEM, or None if nothing is stored yet."""
        if self.backend_name == "keyring":
            try:
                value = keyring.get_password(SERVICE_NAME, username)
                if value is not None:
                    return value
            except keyring.errors.KeyringError:
                pass  # fall through to plaintext
        return self._load_plaintext()

    def delete_private_key(self, username: str) -> None:
        """Remove a stored key from wherever it lives (device revocation,
        Phase 23, will need this). Safe to call even if nothing is stored."""
        if self.backend_name == "keyring":
            try:
                keyring.delete_password(SERVICE_NAME, username)
            except keyring.errors.KeyringError:
                pass
        if os.path.exists(self.plaintext_fallback_path):
            os.remove(self.plaintext_fallback_path)

    def _save_plaintext(self, key_pem: str) -> None:
        directory = os.path.dirname(self.plaintext_fallback_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        # Create with 0600 from the moment the file exists (os.open with an
        # explicit mode), rather than write-then-chmod, which would leave a
        # brief window where the file exists with default (often
        # world-readable) permissions.
        fd = os.open(self.plaintext_fallback_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(key_pem)
        finally:
            os.chmod(self.plaintext_fallback_path, 0o600)  # belt-and-suspenders vs. a restrictive umask

    def _load_plaintext(self) -> str | None:
        if not os.path.exists(self.plaintext_fallback_path):
            return None
        with open(self.plaintext_fallback_path, "r") as f:
            return f.read()
