"""core/vault/recovery_code.py — Phase 39's recovery code (§15).

20 random bytes (160 bits) encoded in Crockford Base32 (no BIP39 word
list — see design doc §15 for why: this is written down once, never
memorized or spoken aloud, so a word list's usual memorability advantage
over random characters doesn't actually apply here). A trailing
Crockford-style checksum character catches a mistyped code immediately,
before it ever reaches the KDF/unwrap step.
"""

import os

RECOVERY_CODE_BYTES = 20  # 160 bits

# Crockford Base32: excludes visually-ambiguous I, L, O from the data
# alphabet (§15). U is deliberately excluded from data too (Crockford's
# own convention, to avoid spelling accidental obscenities) and reserved
# for the checksum alphabet below instead.
_DATA_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
# Crockford's own extended checksum alphabet: the 32 data symbols plus
# five more (*, ~, $, =, U) so a mod-37 checksum has a symbol to map to.
_CHECK_ALPHABET = _DATA_ALPHABET + "*~$=U"

_DATA_INDEX = {ch: i for i, ch in enumerate(_DATA_ALPHABET)}

# Characters people commonly mis-transcribe by hand, normalized before
# decode (Crockford's own recommendation): O -> 0, I/L -> 1.
_NORMALIZE = str.maketrans({
    "O": "0", "o": "0",
    "I": "1", "i": "1",
    "L": "1", "l": "1",
})

GROUP_SIZE = 5  # display grouping only — e.g. "7QME9-KX2C4-..."


class RecoveryCodeError(Exception):
    """Raised when a recovery code fails checksum validation or can't be
    decoded at all — almost always a transcription mistake, caught here
    before it ever reaches the (slow, KDF-based) unwrap step."""


def _encode_crockford(data: bytes) -> str:
    value = int.from_bytes(data, byteorder="big")
    n_chars = (len(data) * 8 + 4) // 5  # ceil(bits / 5); exactly 32 for 20 bytes
    chars = []
    for i in range(n_chars):
        shift = 5 * (n_chars - 1 - i)
        chars.append(_DATA_ALPHABET[(value >> shift) & 0x1F])
    return "".join(chars)


def _decode_crockford(text: str) -> bytes:
    value = 0
    for ch in text:
        try:
            value = (value << 5) | _DATA_INDEX[ch]
        except KeyError:
            raise RecoveryCodeError(f"invalid character {ch!r} in recovery code") from None
    n_bytes = (len(text) * 5) // 8
    try:
        return value.to_bytes(n_bytes, byteorder="big")
    except OverflowError:
        # The decoded value needs more bytes than this many characters
        # should produce — only possible from a truncated/malformed code
        # (the length check right after this call would also catch a
        # too-short *valid* code, but a partial character run can trip
        # this first).
        raise RecoveryCodeError("recovery code is malformed or truncated") from None


def _checksum_char(data: bytes) -> str:
    value = int.from_bytes(data, byteorder="big")
    return _CHECK_ALPHABET[value % 37]


def generate_recovery_code() -> str:
    """Generate a brand-new recovery code, grouped for display, e.g.
    '7QME9-KX2C4-...-Y'. Call exactly once, at first vault setup — the
    raw bytes are never stored anywhere by this module, only used
    (once, by the caller) to derive a KEK that wraps a second copy of
    the DEK."""
    raw = os.urandom(RECOVERY_CODE_BYTES)
    encoded = _encode_crockford(raw)
    check = _checksum_char(raw)
    full = encoded + check
    groups = [full[i:i + GROUP_SIZE] for i in range(0, len(full), GROUP_SIZE)]
    return "-".join(groups)


def normalize_recovery_code(code: str) -> bytes:
    """Parse a user-entered recovery code (with or without dashes/
    lowercase/ambiguous O-I-L characters) back to the raw 20 bytes,
    verifying the trailing checksum character. Raises RecoveryCodeError
    on any mismatch — this is a fast, local, non-KDF check, so a
    mistyped code is caught immediately rather than only discovered
    after a failed (slow) unwrap."""
    cleaned = code.strip().upper().replace("-", "").replace(" ", "")
    cleaned = cleaned.translate(_NORMALIZE)
    if len(cleaned) < 2:
        raise RecoveryCodeError("recovery code is too short")
    data_part, check_part = cleaned[:-1], cleaned[-1]
    raw = _decode_crockford(data_part)
    if len(raw) != RECOVERY_CODE_BYTES:
        raise RecoveryCodeError(
            f"recovery code decodes to {len(raw)} bytes, expected {RECOVERY_CODE_BYTES} "
            "— likely missing or extra characters"
        )
    expected_check = _checksum_char(raw)
    if check_part != expected_check:
        raise RecoveryCodeError("recovery code checksum mismatch — likely mistyped")
    return raw
