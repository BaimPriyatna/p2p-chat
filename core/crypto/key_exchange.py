"""core/crypto/key_exchange.py — Ephemeral X25519 key exchange (Phase 6.1).

Provides ephemeral keypair generation and Diffie-Hellman shared secret
computation using the cryptography library's X25519 implementation.

Identity uses Ed25519 (core/identity/), while session key negotiation uses
ephemeral X25519 keys so each session achieves forward secrecy: compromise of
a long-term identity key does not expose past sessions.
"""

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

X25519_KEY_SIZE = 32


@dataclass
class EphemeralKeypair:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey

    def public_key_bytes(self) -> bytes:
        """32-byte raw public key."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_key_hex(self) -> str:
        """64-character lowercase hex encoding of the raw public key."""
        return self.public_key_bytes().hex()


def generate_ephemeral_keypair() -> EphemeralKeypair:
    """Generate a fresh ephemeral X25519 keypair for a handshake session."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return EphemeralKeypair(private_key=private_key, public_key=public_key)


def ephemeral_public_from_bytes(data: bytes) -> X25519PublicKey:
    """Reconstruct an X25519PublicKey from 32 raw bytes."""
    if len(data) != X25519_KEY_SIZE:
        raise ValueError(f"X25519 public key must be exactly {X25519_KEY_SIZE} bytes, got {len(data)}")
    return X25519PublicKey.from_public_bytes(data)


def ephemeral_public_from_hex(hex_str: str) -> X25519PublicKey:
    """Reconstruct an X25519PublicKey from a 64-char hex string."""
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValueError(f"invalid hex for X25519 public key: {e}") from e
    return ephemeral_public_from_bytes(raw)


def compute_shared_secret(
    private_key: X25519PrivateKey, peer_public_key: X25519PublicKey
) -> bytes:
    """Compute raw 32-byte Diffie-Hellman shared secret between our private key
    and peer's ephemeral public key."""
    return private_key.exchange(peer_public_key)
