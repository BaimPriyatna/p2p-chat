"""core/crypto/ — Cryptographic primitives and protocols for peerc.

    key_exchange.py — Ephemeral X25519 keypair generation and DH exchange (Phase 6.1)
    handshake.py    — Secure authenticated handshake state machine & transport (Phase 6.2)
    kdf.py          — HKDF-SHA256 session key derivation (Phase 7)
    encryption.py   — ChaCha20-Poly1305 AEAD stream/frame encryption (Phase 8)
"""

from .encryption import (
    HEADER_LEN,
    KEY_LEN,
    MAX_SEQUENCE,
    MIN_FRAME_LEN,
    NONCE_LEN,
    SEQUENCE_LEN,
    TAG_LEN,
    AuthenticationError,
    EncryptedFrame,
    EncryptionError,
    FrameDecryptor,
    FrameEncryptor,
    NonceReuseError,
    ReplayError,
    SequenceOverflowError,
    SessionCipher,
    decrypt,
    decrypt_frame,
    encrypt,
    encrypt_frame,
)
from .handshake import (
    HANDSHAKE_TIMEOUT,
    DeviceRevokedError,
    HandshakeError,
    HandshakeProtocolError,
    HandshakeResult,
    HandshakeTimeoutError,
    IdentityVerificationError,
    KeyChangedError,
    NonceCache,
    SignatureVerificationError,
    compute_final_transcript_hash,
    compute_initiator_transcript,
    compute_responder_transcript,
    perform_handshake_initiator,
    perform_handshake_responder,
)
from .kdf import (
    KDFError,
    SessionKeys,
    derive_session_keys,
)
from .key_exchange import (
    EphemeralKeypair,
    compute_shared_secret,
    ephemeral_public_from_bytes,
    ephemeral_public_from_hex,
    generate_ephemeral_keypair,
)

__all__ = [
    "EphemeralKeypair",
    "generate_ephemeral_keypair",
    "ephemeral_public_from_bytes",
    "ephemeral_public_from_hex",
    "compute_shared_secret",
    "HANDSHAKE_TIMEOUT",
    "HandshakeError",
    "HandshakeTimeoutError",
    "IdentityVerificationError",
    "SignatureVerificationError",
    "DeviceRevokedError",
    "KeyChangedError",
    "HandshakeProtocolError",
    "HandshakeResult",
    "NonceCache",
    "compute_responder_transcript",
    "compute_initiator_transcript",
    "compute_final_transcript_hash",
    "perform_handshake_initiator",
    "perform_handshake_responder",
    "KDFError",
    "SessionKeys",
    "derive_session_keys",
    "KEY_LEN",
    "NONCE_LEN",
    "TAG_LEN",
    "SEQUENCE_LEN",
    "HEADER_LEN",
    "MIN_FRAME_LEN",
    "MAX_SEQUENCE",
    "EncryptionError",
    "AuthenticationError",
    "ReplayError",
    "NonceReuseError",
    "SequenceOverflowError",
    "EncryptedFrame",
    "encrypt",
    "decrypt",
    "encrypt_frame",
    "decrypt_frame",
    "FrameEncryptor",
    "FrameDecryptor",
    "SessionCipher",
]


