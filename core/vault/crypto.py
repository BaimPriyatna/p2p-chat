"""core/vault/crypto.py — low-level primitives for Phase 39's envelope
encryption (Secure Storage). See docs/SECURE_STORAGE_DESIGN.md §2, §13, §16.

Two primitives only, deliberately narrow:
  - Scrypt KDF: turns a low-entropy secret (passphrase or recovery code)
    plus a random salt into a KEK (Key Encryption Key). Never used to
    encrypt data directly — only ever to wrap/unwrap a DEK.
  - AES-256-GCM wrap/unwrap: uses a KEK to wrap/unwrap the DEK (Data
    Encryption Key). A fresh random 12-byte nonce every time (§16) —
    nonces aren't secret, they only need to be unique per key. GCM's own
    auth tag doubles as the "wrong passphrase" verifier (§13) — no
    separate verifier hash is stored or needed.
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# RFC 7914's own recommendation for interactive use — deliberately not
# user-configurable (design doc §13): a value picked wrong in either
# direction (too fast = weaker, too slow = the app hangs on every
# unlock) is worse than one sane fixed default.
SCRYPT_N = 131072  # 2**17
SCRYPT_R = 8
SCRYPT_P = 1

SALT_LEN = 16    # bytes — passphrase_salt / recovery_salt
NONCE_LEN = 12   # bytes — AES-GCM's standard 96-bit nonce
KEK_LEN = 32     # bytes — AES-256 key size
DEK_LEN = 32     # bytes — AES-256 key size


class VaultCryptoError(Exception):
    """Base class for vault envelope-encryption errors."""


class WrongSecretError(VaultCryptoError):
    """Raised when unwrapping fails — the passphrase or recovery code
    doesn't match what wrapped this DEK (or the ciphertext was
    tampered/corrupted). Deliberately doesn't distinguish those two
    cases — same reasoning as core/crypto/encryption.py's
    DecryptionError: that distinction itself can leak information to
    someone probing the vault."""


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def new_dek() -> bytes:
    """Generate a fresh Data Encryption Key. Called exactly once per
    vault, at first setup (create_vault) — never regenerated except via
    an explicit key-rotation flow, which is out of scope for 39.1."""
    return os.urandom(DEK_LEN)


def derive_kek(secret: bytes, salt: bytes) -> bytes:
    """Scrypt(secret, salt) -> 32-byte KEK. `secret` is passphrase bytes
    (UTF-8 encoded by the caller) or normalized recovery-code bytes —
    this function doesn't care which, it's just the KDF step."""
    kdf = Scrypt(salt=salt, length=KEK_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(secret)


def wrap_dek(kek: bytes, dek: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt the DEK under a KEK. Returns (ciphertext, nonce);
    both are stored (not secret by themselves) in the vault keyfile."""
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(kek).encrypt(nonce, dek, None)
    return ciphertext, nonce


def unwrap_dek(kek: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    """Decrypt the DEK. Raises WrongSecretError if the KEK doesn't match
    (wrong passphrase/recovery code) or the ciphertext was tampered —
    GCM's auth tag is the only "is this the right secret" check needed,
    no separate verifier hash (§13)."""
    try:
        return AESGCM(kek).decrypt(nonce, ciphertext, None)
    except InvalidTag as e:
        raise WrongSecretError(
            "wrong passphrase/recovery code, or corrupted vault keyfile"
        ) from e
