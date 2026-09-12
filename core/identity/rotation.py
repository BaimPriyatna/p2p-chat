"""core/identity/rotation.py — Phase 40: Device Key Rotation.

A planned key rotation replaces a device's Ed25519 keypair while carrying the
TRUSTED status that peer devices have already assigned forward to the new
device_id, without requiring fresh TOFU.

The proof is a Transition Certificate: the OLD private key signs a canonical
payload that contains both device_ids (old and new) and both public keys.
Any peer that already trusts the old device_id can verify this certificate
and automatically extend that trust to the new device_id.

Compromise-triggered rotation deliberately produces NO certificate — the
compromised key cannot be trusted to vouch for its own replacement, so
peers must TOFU the new identity from scratch (SECURITY_MODEL.md §16).
"""

import base64
import struct
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .device_identity import DeviceKeypair, public_key_from_bytes

# Domain-separation prefix — ensures rotation signatures cannot be
# replayed as any other kind of peerc signature.
_ROTATION_DOMAIN = b"peerc-key-rotation\x00"


class RotationError(Exception):
    """Raised when a rotation or verification fails."""


@dataclass
class TransitionCertificate:
    """Cryptographic proof that a device intentionally rotated its key.

    The signature covers a canonical payload (see _build_payload) that
    binds old_device_id, new_device_id, old_public_key, new_public_key,
    and timestamp together under the domain-separation prefix.

    All key fields are base64-encoded raw Ed25519 public key bytes (32 bytes),
    matching the existing convention in identity_file.py and TrustStore.
    """

    old_device_id: str
    old_public_key: str   # base64(raw 32 bytes)
    new_device_id: str
    new_public_key: str   # base64(raw 32 bytes)
    timestamp: float
    signature: str        # base64(64-byte Ed25519 signature by old key)


def create_transition_certificate(
    old_keypair: DeviceKeypair,
    new_keypair: DeviceKeypair,
) -> TransitionCertificate:
    """Sign a transition from *old_keypair* to *new_keypair*.

    The old private key signs the canonical payload.  Call this before
    discarding/replacing the old private key in KeyStore — once the old
    key is gone you cannot produce this certificate.

    Raises RotationError if old and new keypair are the same device_id.
    """
    if old_keypair.device_id == new_keypair.device_id:
        raise RotationError(
            "old and new keypair have the same device_id — no rotation needed"
        )

    old_pub_b64 = base64.b64encode(old_keypair.public_key_bytes()).decode("ascii")
    new_pub_b64 = base64.b64encode(new_keypair.public_key_bytes()).decode("ascii")
    ts = time.time()

    payload = _build_payload(
        old_device_id=old_keypair.device_id,
        new_device_id=new_keypair.device_id,
        old_public_key_b64=old_pub_b64,
        new_public_key_b64=new_pub_b64,
        timestamp=ts,
    )
    sig_bytes = old_keypair.sign(payload)

    return TransitionCertificate(
        old_device_id=old_keypair.device_id,
        old_public_key=old_pub_b64,
        new_device_id=new_keypair.device_id,
        new_public_key=new_pub_b64,
        timestamp=ts,
        signature=base64.b64encode(sig_bytes).decode("ascii"),
    )


def verify_transition_certificate(cert: TransitionCertificate) -> bool:
    """Verify that *cert* was signed by the private key matching cert.old_public_key.

    Returns True on a valid signature, False on any cryptographic failure or
    malformed data.  Raises nothing — callers can treat False as "untrusted".
    """
    try:
        old_pub_bytes = base64.b64decode(cert.old_public_key)
        sig_bytes = base64.b64decode(cert.signature)

        old_pub_key: Ed25519PublicKey = public_key_from_bytes(old_pub_bytes)

        payload = _build_payload(
            old_device_id=cert.old_device_id,
            new_device_id=cert.new_device_id,
            old_public_key_b64=cert.old_public_key,
            new_public_key_b64=cert.new_public_key,
            timestamp=cert.timestamp,
        )
        old_pub_key.verify(sig_bytes, payload)
        return True
    except (InvalidSignature, Exception):
        return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_payload(
    *,
    old_device_id: str,
    new_device_id: str,
    old_public_key_b64: str,
    new_public_key_b64: str,
    timestamp: float,
) -> bytes:
    """Canonical payload signed/verified for a transition certificate.

    Format (all concatenated, no length-prefixes needed since every field
    is either fixed-length or separated by a NUL byte that cannot appear in
    hex device_ids or base64 strings):

        DOMAIN_PREFIX           (b"peerc-key-rotation\\x00")
        old_device_id           (UTF-8, 64 hex chars)
        NUL (0x00)
        new_device_id           (UTF-8, 64 hex chars)
        NUL (0x00)
        old_public_key_b64      (UTF-8, base64)
        NUL (0x00)
        new_public_key_b64      (UTF-8, base64)
        NUL (0x00)
        timestamp               (8 bytes, big-endian IEEE 754 double)
    """
    return (
        _ROTATION_DOMAIN
        + old_device_id.encode("utf-8")
        + b"\x00"
        + new_device_id.encode("utf-8")
        + b"\x00"
        + old_public_key_b64.encode("utf-8")
        + b"\x00"
        + new_public_key_b64.encode("utf-8")
        + b"\x00"
        + struct.pack(">d", timestamp)
    )
