"""core/crypto/kdf.py — Session Key Derivation (Phase 7).

Derives symmetric encryption session keys and unique session IDs from the
ephemeral X25519 shared secret and authenticated handshake transcript hash.

Key properties:
    - HKDF-SHA256 (RFC 5869): Cryptographically sound key derivation.
    - Domain separation: Distinct info tags for initiator->responder,
      responder->initiator, and session identifier.
    - Directional keys: Initiator tx_key matches Responder rx_key and vice-versa,
      preventing key reuse and reflection attacks.
    - Transcript binding: Uses the 32-byte handshake transcript hash as salt,
      cryptographically binding derived keys to the exact authenticated session.
"""

from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_LEN = 32         # 256-bit keys for ChaCha20-Poly1305 (Phase 8)
SESSION_ID_LEN = 16  # 128-bit unique session identifier

INFO_INIT_TO_RESP = b"peerc-v2:initiator-to-responder"
INFO_RESP_TO_INIT = b"peerc-v2:responder-to-initiator"
INFO_SESSION_ID = b"peerc-v2:session-id"


class KDFError(Exception):
    """Raised when key derivation fails or inputs are invalid."""


@dataclass(frozen=True)
class SessionKeys:
    """Holds directional symmetric session keys and a public session ID."""

    send_key: bytes      # 32 bytes for outgoing traffic encryption
    recv_key: bytes      # 32 bytes for incoming traffic decryption
    session_id: str      # Hex string representation of session identifier

    def __repr__(self) -> str:
        return f"SessionKeys(session_id={self.session_id!r}, send_key=***, recv_key=***)"


def _hkdf_expand(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Execute HKDF-SHA256 extract-and-expand."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def derive_session_keys(
    shared_secret: bytes,
    salt: bytes,
    is_initiator: bool,
) -> SessionKeys:
    """Derive directional session keys using HKDF-SHA256.

    Args:
        shared_secret: 32-byte ephemeral X25519 shared secret.
        salt: 32-byte handshake transcript hash (acts as HKDF salt).
        is_initiator: True if this peer initiated the handshake, False if responder.

    Returns:
        SessionKeys instance containing send_key, recv_key, and session_id.

    Raises:
        KDFError: If inputs are invalid or derivation fails.
    """
    if not isinstance(shared_secret, (bytes, bytearray)):
        raise KDFError(f"shared_secret must be bytes, got {type(shared_secret).__name__}")
    if len(shared_secret) != 32:
        raise KDFError(f"shared_secret must be exactly 32 bytes, got {len(shared_secret)}")

    if not isinstance(salt, (bytes, bytearray)):
        raise KDFError(f"salt must be bytes, got {type(salt).__name__}")
    if len(salt) != 32:
        raise KDFError(f"salt must be exactly 32 bytes, got {len(salt)}")

    salt_bytes = bytes(salt)
    secret_bytes = bytes(shared_secret)

    try:
        init_to_resp_key = _hkdf_expand(
            ikm=secret_bytes,
            salt=salt_bytes,
            info=INFO_INIT_TO_RESP,
            length=KEY_LEN,
        )
        resp_to_init_key = _hkdf_expand(
            ikm=secret_bytes,
            salt=salt_bytes,
            info=INFO_RESP_TO_INIT,
            length=KEY_LEN,
        )
        session_id_bytes = _hkdf_expand(
            ikm=secret_bytes,
            salt=salt_bytes,
            info=INFO_SESSION_ID,
            length=SESSION_ID_LEN,
        )
    except Exception as e:
        raise KDFError(f"HKDF derivation failed: {e}") from e

    session_id = session_id_bytes.hex()

    if is_initiator:
        return SessionKeys(
            send_key=init_to_resp_key,
            recv_key=resp_to_init_key,
            session_id=session_id,
        )
    else:
        return SessionKeys(
            send_key=resp_to_init_key,
            recv_key=init_to_resp_key,
            session_id=session_id,
        )
