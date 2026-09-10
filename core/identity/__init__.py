"""core.identity — Ed25519 device identity (IMPLEMENTATION_PLAN.md Phase 3).

    device_identity.py — Ed25519 keypair generation, device_id = SHA256(pubkey)
    key_storage.py      — KeyStore (OS keyring, plaintext-file fallback)
    fingerprint.py       — human-readable device_id formatting
    identity_file.py     — load_or_create_identity(): ties the above together
"""

from .device_identity import (
    DeviceKeypair,
    compute_device_id,
    generate_keypair,
    keypair_from_private_pem,
    public_key_from_bytes,
)
from .fingerprint import format_fingerprint, short_fingerprint
from .identity_file import (
    DEFAULT_IDENTITY_FILE,
    DeviceIdentity,
    IdentityError,
    load_or_create_identity,
)
from .key_storage import KeyStore, KeyStoreError

__all__ = [
    "DeviceKeypair",
    "compute_device_id",
    "generate_keypair",
    "keypair_from_private_pem",
    "public_key_from_bytes",
    "format_fingerprint",
    "short_fingerprint",
    "DEFAULT_IDENTITY_FILE",
    "DeviceIdentity",
    "IdentityError",
    "load_or_create_identity",
    "KeyStore",
    "KeyStoreError",
]
