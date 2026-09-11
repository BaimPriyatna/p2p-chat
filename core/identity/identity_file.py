"""core/identity/identity_file.py — the Phase 3.3 identity file + load_or_create.

Two things are persisted, deliberately kept apart:
  - the PRIVATE key, via KeyStore (core/identity/key_storage.py) — OS
    keyring, or a 0600 plaintext file fallback. Never written into the
    identity JSON file below.
  - PUBLIC metadata — device_id, public_key, display name, created_at —
    in a plain JSON file. Safe to read, back up, or hand to another peer;
    it contains nothing secret.

This is the direct replacement for discovery.py's old
load_or_create_identity(), which generated a bare random UUID. See
Phase 3.0 in IMPLEMENTATION_PLAN.md for why that wasn't good enough.
"""

import base64
import json
import os
import time
from dataclasses import dataclass

from .device_identity import DeviceKeypair, generate_keypair, keypair_from_private_pem
from .key_storage import KeyStore

IDENTITY_SCHEMA_VERSION = 1
DEFAULT_IDENTITY_DIR = os.path.expanduser("~/.peerc")
DEFAULT_IDENTITY_FILE = os.path.join(DEFAULT_IDENTITY_DIR, "identity.json")
KEYRING_USERNAME = "device-identity"  # one identity per device, so this is a fixed key


class IdentityError(Exception):
    """Raised when the identity file and key storage disagree or are corrupt."""


@dataclass
class DeviceIdentity:
    keypair: DeviceKeypair
    name: str
    created_at: float
    storage_backend: str  # "keyring" or "plaintext-file" — worth surfacing to the user

    @property
    def device_id(self) -> str:
        return self.keypair.device_id


def load_or_create_identity(
    name: str | None = None,
    identity_file: str = DEFAULT_IDENTITY_FILE,
    key_store: KeyStore | None = None,
) -> DeviceIdentity:
    """Load the existing device identity, or generate one on first run.

    `name` is only used on first run (to set the initial display name);
    on subsequent runs the name stored in the identity file wins, matching
    the old UUID-based load_or_create_identity()'s behavior.
    """
    key_store = key_store or KeyStore()

    if os.path.exists(identity_file):
        return _load_existing(identity_file, key_store)
    return _create_new(name or "peer", identity_file, key_store)


def _load_existing(identity_file: str, key_store: KeyStore) -> DeviceIdentity:
    with open(identity_file, "r") as f:
        meta = json.load(f)

    pem = key_store.load_private_key(KEYRING_USERNAME)
    if pem is None:
        raise IdentityError(
            f"identity file {identity_file!r} exists but its private key is "
            "missing from storage — the device's identity can't be proven "
            "without it. If the key is genuinely gone, delete the identity "
            "file to generate a fresh identity (this changes your device_id)."
        )

    keypair = keypair_from_private_pem(pem)
    if keypair.device_id != meta.get("device_id"):
        raise IdentityError(
            f"stored private key does not match device_id in {identity_file!r} "
            "— identity file and key storage are out of sync"
        )

    return DeviceIdentity(
        keypair=keypair,
        name=meta.get("name") or "peer",
        created_at=meta.get("created_at", time.time()),
        storage_backend=key_store.backend_name,
    )


def _create_new(name: str, identity_file: str, key_store: KeyStore) -> DeviceIdentity:
    keypair = generate_keypair()
    created_at = time.time()

    backend_used = key_store.save_private_key(KEYRING_USERNAME, keypair.private_key_pem())

    directory = os.path.dirname(identity_file)
    if directory:
        os.makedirs(directory, exist_ok=True)

    meta = {
        "version": IDENTITY_SCHEMA_VERSION,
        "device_id": keypair.device_id,
        "public_key": base64.b64encode(keypair.public_key_bytes()).decode("ascii"),
        "name": name,
        "created_at": created_at,
    }
    with open(identity_file, "w") as f:
        json.dump(meta, f, indent=2)

    return DeviceIdentity(keypair=keypair, name=name, created_at=created_at, storage_backend=backend_used)
