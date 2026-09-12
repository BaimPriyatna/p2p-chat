"""core/transfer/hashing.py — SHA-256 integrity hashing (Phase 17).

Provides streaming and incremental SHA-256 checksum calculation for file transfer integrity.
"""

import hashlib
from typing import Optional

DEFAULT_HASH_CHUNK_SIZE = 64 * 1024  # 64 KB


def sha256_file(filepath: str, chunk_size: int = DEFAULT_HASH_CHUNK_SIZE) -> str:
    """Compute the SHA-256 hex digest of a file on disk in streaming chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


class IncrementalHasher:
    """Maintains a rolling SHA-256 hash as binary chunks arrive."""

    def __init__(self):
        self._hasher = hashlib.sha256()
        self._bytes_hashed = 0

    @property
    def bytes_hashed(self) -> int:
        return self._bytes_hashed

    def update(self, data: bytes) -> None:
        self._hasher.update(data)
        self._bytes_hashed += len(data)

    def hexdigest(self) -> str:
        return self._hasher.hexdigest()

    def digest(self) -> bytes:
        return self._hasher.digest()
