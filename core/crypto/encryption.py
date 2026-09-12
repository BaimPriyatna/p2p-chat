"""core/crypto/encryption.py — Symmetric AEAD Encryption (Phase 8).

Provides authenticated symmetric stream and frame encryption using ChaCha20-Poly1305
(RFC 8439). Encrypted frames carry sequence numbers, explicit nonces, ciphertexts,
and Poly1305 authentication tags.

Key properties:
    - AEAD (RFC 8439): ChaCha20 stream cipher combined with Poly1305 MAC.
    - Wire framing:
        [8 bytes: sequence uint64 (big-endian)]
        [12 bytes: nonce]
        [N bytes: ciphertext]
        [16 bytes: Poly1305 authentication tag]
    - Associated Authenticated Data (AAD): Sequence number (and optional extra AAD)
      is cryptographically bound to the authentication tag, preventing any in-transit
      tampering of sequence numbers or header metadata.
    - Strict Replay & Reordering Protection: FrameDecryptor rejects out-of-order,
      replayed, or duplicate sequence numbers.
    - Nonce Uniqueness: Guarantees no nonce reuse for any given key.
    - Directional Session Support: Directly pairs with Phase 7 SessionKeys via SessionCipher.
"""

from dataclasses import dataclass
import struct
from typing import Optional, Set

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# RFC 8439 Constants
KEY_LEN = 32          # 256-bit symmetric key
NONCE_LEN = 12        # 96-bit AEAD nonce
TAG_LEN = 16          # 128-bit Poly1305 authentication tag
SEQUENCE_LEN = 8      # 64-bit unsigned big-endian sequence number
HEADER_LEN = SEQUENCE_LEN + NONCE_LEN  # 20 bytes
MIN_FRAME_LEN = HEADER_LEN + TAG_LEN   # 36 bytes (for 0-byte plaintext)
MAX_SEQUENCE = 0xFFFFFFFFFFFFFFFF      # uint64 max


class EncryptionError(Exception):
    """Base exception for all encryption and decryption failures."""


class AuthenticationError(EncryptionError):
    """Raised when authentication tag validation fails (tampering or wrong key)."""


class ReplayError(EncryptionError):
    """Raised when a received frame has an invalid or replayed sequence number."""


class NonceReuseError(EncryptionError):
    """Raised when an attempt is made to encrypt or decrypt with a reused nonce."""


class SequenceOverflowError(EncryptionError):
    """Raised when sequence counter exceeds 64-bit integer limit."""


@dataclass(frozen=True)
class EncryptedFrame:
    """An authenticated encrypted wire frame.

    Attributes:
        sequence: 64-bit monotonically increasing message counter.
        nonce: 12-byte AEAD nonce.
        ciphertext: Encrypted payload bytes (excluding the 16-byte tag).
        tag: 16-byte Poly1305 authentication tag.
    """

    sequence: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def __post_init__(self) -> None:
        if not (0 <= self.sequence <= MAX_SEQUENCE):
            raise EncryptionError(f"Sequence out of 64-bit bounds: {self.sequence}")
        if len(self.nonce) != NONCE_LEN:
            raise EncryptionError(f"Nonce must be exactly {NONCE_LEN} bytes, got {len(self.nonce)}")
        if len(self.tag) != TAG_LEN:
            raise EncryptionError(f"Tag must be exactly {TAG_LEN} bytes, got {len(self.tag)}")

    @property
    def ciphertext_and_tag(self) -> bytes:
        """Ciphertext combined with the 16-byte Poly1305 tag."""
        return self.ciphertext + self.tag

    def pack(self) -> bytes:
        """Serialize frame to wire format: [sequence:8B][nonce:12B][ciphertext:NB][tag:16B]."""
        header = struct.pack(">Q", self.sequence) + self.nonce
        return header + self.ciphertext + self.tag

    @classmethod
    def unpack(cls, data: bytes) -> "EncryptedFrame":
        """Deserialize wire format bytes into an EncryptedFrame instance."""
        if not isinstance(data, (bytes, bytearray)):
            raise EncryptionError(f"Frame data must be bytes, got {type(data).__name__}")
        if len(data) < MIN_FRAME_LEN:
            raise EncryptionError(
                f"Frame data too short: expected at least {MIN_FRAME_LEN} bytes, got {len(data)}"
            )

        seq_bytes = data[:SEQUENCE_LEN]
        (sequence,) = struct.unpack(">Q", seq_bytes)
        nonce = data[SEQUENCE_LEN:HEADER_LEN]
        tag = data[-TAG_LEN:]
        ciphertext = data[HEADER_LEN:-TAG_LEN]

        return cls(
            sequence=sequence,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )


def _format_aad(sequence: int, associated_data: Optional[bytes] = None) -> bytes:
    """Construct Associated Authenticated Data binding sequence number and extra context."""
    seq_bytes = struct.pack(">Q", sequence)
    if associated_data:
        return seq_bytes + bytes(associated_data)
    return seq_bytes


def encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Encrypt raw plaintext using ChaCha20-Poly1305.

    Returns:
        Combined bytes consisting of ciphertext + 16-byte authentication tag.
    """
    if len(key) != KEY_LEN:
        raise EncryptionError(f"Key must be exactly {KEY_LEN} bytes, got {len(key)}")
    if len(nonce) != NONCE_LEN:
        raise EncryptionError(f"Nonce must be exactly {NONCE_LEN} bytes, got {len(nonce)}")

    try:
        cipher = ChaCha20Poly1305(key)
        return cipher.encrypt(nonce, plaintext, associated_data)
    except Exception as e:
        raise EncryptionError(f"ChaCha20-Poly1305 encryption failed: {e}") from e


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext_and_tag: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Decrypt and authenticate ciphertext using ChaCha20-Poly1305.

    Returns:
        Original decrypted plaintext bytes.

    Raises:
        AuthenticationError: If tag validation fails or data was tampered with.
        EncryptionError: If parameters are invalid.
    """
    if len(key) != KEY_LEN:
        raise EncryptionError(f"Key must be exactly {KEY_LEN} bytes, got {len(key)}")
    if len(nonce) != NONCE_LEN:
        raise EncryptionError(f"Nonce must be exactly {NONCE_LEN} bytes, got {len(nonce)}")
    if len(ciphertext_and_tag) < TAG_LEN:
        raise EncryptionError(
            f"Data too short to contain tag: got {len(ciphertext_and_tag)} bytes, minimum {TAG_LEN}"
        )

    try:
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, ciphertext_and_tag, associated_data)
    except InvalidTag as e:
        raise AuthenticationError("ChaCha20-Poly1305 authentication failed: invalid tag or tampered data") from e
    except Exception as e:
        raise EncryptionError(f"Decryption failed: {e}") from e


def encrypt_frame(
    key: bytes,
    sequence: int,
    plaintext: bytes,
    nonce: Optional[bytes] = None,
    associated_data: Optional[bytes] = None,
) -> EncryptedFrame:
    """Encrypt plaintext into an EncryptedFrame with sequence bound into AAD.

    If nonce is None, a default 12-byte deterministic nonce (4 zero bytes + 8 bytes sequence)
    is generated.
    """
    if nonce is None:
        nonce = b"\x00" * 4 + struct.pack(">Q", sequence)

    aad = _format_aad(sequence, associated_data)
    ct_and_tag = encrypt(key, nonce, plaintext, associated_data=aad)

    ciphertext = ct_and_tag[:-TAG_LEN]
    tag = ct_and_tag[-TAG_LEN:]

    return EncryptedFrame(
        sequence=sequence,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
    )


def decrypt_frame(
    key: bytes,
    frame: EncryptedFrame,
    expected_sequence: Optional[int] = None,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Authenticate and decrypt an EncryptedFrame.

    If expected_sequence is specified, verifies that frame.sequence matches.
    """
    if expected_sequence is not None and frame.sequence != expected_sequence:
        raise ReplayError(
            f"Sequence mismatch: expected sequence {expected_sequence}, got {frame.sequence}"
        )

    aad = _format_aad(frame.sequence, associated_data)
    return decrypt(key, frame.nonce, frame.ciphertext_and_tag, associated_data=aad)


class FrameEncryptor:
    """Stateful frame encryptor maintaining sequence counter and nonce generation."""

    def __init__(self, key: bytes, session_id: Optional[str] = None):
        if len(key) != KEY_LEN:
            raise EncryptionError(f"Key must be exactly {KEY_LEN} bytes, got {len(key)}")
        self._key = key
        self._session_id = session_id
        self._next_sequence = 0
        self._seen_nonces: Set[bytes] = set()

        # Deterministic salt prefix (4 bytes) derived from session_id or zeros
        if session_id:
            try:
                sid_bytes = bytes.fromhex(session_id)
                self._salt = sid_bytes[:4].ljust(4, b"\x00")
            except ValueError:
                self._salt = session_id.encode("utf-8")[:4].ljust(4, b"\x00")
        else:
            self._salt = b"\x00" * 4

    @property
    def next_sequence(self) -> int:
        return self._next_sequence

    def _generate_nonce(self, sequence: int) -> bytes:
        return self._salt + struct.pack(">Q", sequence)

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
    ) -> EncryptedFrame:
        """Encrypt plaintext into the next sequential EncryptedFrame."""
        if self._next_sequence > MAX_SEQUENCE:
            raise SequenceOverflowError("Sequence counter exceeded 64-bit maximum limit")

        seq = self._next_sequence
        nonce = self._generate_nonce(seq)

        if nonce in self._seen_nonces:
            raise NonceReuseError(f"Nonce reuse detected for nonce {nonce.hex()}")
        self._seen_nonces.add(nonce)

        frame = encrypt_frame(
            self._key,
            sequence=seq,
            plaintext=plaintext,
            nonce=nonce,
            associated_data=associated_data,
        )
        self._next_sequence += 1
        return frame

    def encrypt_raw(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Encrypt plaintext and return packed wire bytes."""
        return self.encrypt(plaintext, associated_data=associated_data).pack()


class FrameDecryptor:
    """Stateful frame decryptor enforcing strictly monotonic sequences and nonce uniqueness."""

    def __init__(
        self,
        key: bytes,
        session_id: Optional[str] = None,
        strict_order: bool = True,
    ):
        if len(key) != KEY_LEN:
            raise EncryptionError(f"Key must be exactly {KEY_LEN} bytes, got {len(key)}")
        self._key = key
        self._session_id = session_id
        self._strict_order = strict_order
        self._last_sequence: Optional[int] = None
        self._seen_sequences: Set[int] = set()
        self._seen_nonces: Set[bytes] = set()

    @property
    def last_sequence(self) -> Optional[int]:
        return self._last_sequence

    def decrypt(
        self,
        frame: EncryptedFrame,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Authenticate and decrypt an EncryptedFrame, enforcing sequence rules."""
        if self._strict_order:
            expected = 0 if self._last_sequence is None else self._last_sequence + 1
            if frame.sequence != expected:
                raise ReplayError(
                    f"Out of order sequence: expected {expected}, got {frame.sequence}"
                )
        else:
            if frame.sequence in self._seen_sequences:
                raise ReplayError(f"Duplicate sequence replayed: {frame.sequence}")
            if self._last_sequence is not None and frame.sequence <= self._last_sequence:
                raise ReplayError(
                    f"Sequence regressed or replayed: {frame.sequence} <= {self._last_sequence}"
                )

        if frame.nonce in self._seen_nonces:
            raise NonceReuseError(f"Duplicate nonce detected: {frame.nonce.hex()}")

        plaintext = decrypt_frame(
            self._key,
            frame=frame,
            expected_sequence=frame.sequence,
            associated_data=associated_data,
        )

        self._seen_sequences.add(frame.sequence)
        self._seen_nonces.add(frame.nonce)
        self._last_sequence = frame.sequence

        return plaintext

    def decrypt_raw(
        self,
        data: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Unpack wire bytes and decrypt frame."""
        frame = EncryptedFrame.unpack(data)
        return self.decrypt(frame, associated_data=associated_data)


class SessionCipher:
    """Directional symmetric cipher pairing FrameEncryptor and FrameDecryptor.

    Bridges Phase 7 SessionKeys with Phase 8 ChaCha20-Poly1305 encryption.
    """

    def __init__(
        self,
        send_key: bytes,
        recv_key: bytes,
        session_id: Optional[str] = None,
        strict_order: bool = True,
    ):
        self.encryptor = FrameEncryptor(send_key, session_id=session_id)
        self.decryptor = FrameDecryptor(recv_key, session_id=session_id, strict_order=strict_order)
        self.session_id = session_id

    @classmethod
    def from_session_keys(
        cls,
        session_keys: object,
        strict_order: bool = True,
    ) -> "SessionCipher":
        """Construct SessionCipher directly from a Phase 7 SessionKeys instance."""
        send_key = getattr(session_keys, "send_key")
        recv_key = getattr(session_keys, "recv_key")
        session_id = getattr(session_keys, "session_id", None)
        return cls(
            send_key=send_key,
            recv_key=recv_key,
            session_id=session_id,
            strict_order=strict_order,
        )

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Encrypt plaintext into wire-packed frame bytes."""
        return self.encryptor.encrypt_raw(plaintext, associated_data=associated_data)

    def decrypt(
        self,
        data: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Unpack and decrypt wire-packed frame bytes into original plaintext."""
        return self.decryptor.decrypt_raw(data, associated_data=associated_data)
