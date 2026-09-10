"""core/identity/device_identity.py — Ed25519 device keypair + device_id.

Implements IMPLEMENTATION_PLAN.md Phase 3.1/3.2. A device's identity is an
Ed25519 keypair generated once and kept for the device's lifetime — NOT a
random UUID (see Phase 3.0's rationale in IMPLEMENTATION_PLAN.md): a
keypair lets a peer *prove* ownership of its identity via a signature,
which a bare UUID never could — anyone could claim any UUID.

device_id = SHA256(raw public key bytes), hex-encoded. Identity is
provably *derived from* — not just paired with — the key that backs it.

Uses the `cryptography` library's Ed25519 implementation exclusively; no
crypto primitives are implemented here (per Phase 3's explicit instruction
not to roll our own).
"""

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass
class DeviceKeypair:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    device_id: str  # sha256(raw public key bytes), 64-char hex

    def public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def private_key_pem(self) -> str:
        """PKCS8 PEM, unencrypted — encryption-at-rest is KeyStore's job
        (OS keyring), not this module's."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)


def compute_device_id(public_key_bytes: bytes) -> str:
    return hashlib.sha256(public_key_bytes).hexdigest()


def generate_keypair() -> DeviceKeypair:
    """Generate a brand new Ed25519 keypair (first-run device identity)."""
    private_key = Ed25519PrivateKey.generate()
    return _keypair_from_private_key(private_key)


def keypair_from_private_pem(pem: str) -> DeviceKeypair:
    """Reconstruct a DeviceKeypair from a stored PKCS8 PEM private key."""
    private_key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("PEM does not contain an Ed25519 private key")
    return _keypair_from_private_key(private_key)


def _keypair_from_private_key(private_key: Ed25519PrivateKey) -> DeviceKeypair:
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return DeviceKeypair(
        private_key=private_key,
        public_key=public_key,
        device_id=compute_device_id(pub_bytes),
    )


def public_key_from_bytes(data: bytes) -> Ed25519PublicKey:
    """Reconstruct a peer's public key from the raw bytes they advertised.

    Used later (Phase 6, handshake) to verify a peer's signature — kept
    here since it's the natural counterpart to public_key_bytes() above.
    """
    return Ed25519PublicKey.from_public_bytes(data)
