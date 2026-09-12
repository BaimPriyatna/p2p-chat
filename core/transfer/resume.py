"""core/transfer/resume.py — Partial file tracking and atomic finalization (Phase 16).

Handles .part file naming, inspection of existing downloaded bytes, cleanup,
and atomic renaming on verified transfer completion.
"""

import os
from typing import Optional

PART_EXTENSION = ".part"


def get_part_path(dest_path: str) -> str:
    """Return the temporary partial file path for a destination path."""
    return dest_path + PART_EXTENSION


def get_partial_bytes(part_path: str) -> int:
    """Return the number of bytes already written to a partial file, or 0 if absent."""
    if os.path.isfile(part_path):
        try:
            return os.path.getsize(part_path)
        except OSError:
            return 0
    return 0


def cleanup_part_file(part_path: str) -> None:
    """Delete a partial file if it exists."""
    if os.path.exists(part_path):
        try:
            os.remove(part_path)
        except OSError:
            pass


def finalize_part_file(part_path: str, dest_path: str) -> None:
    """Atomically rename a verified partial file to its final destination."""
    if not os.path.isfile(part_path):
        raise FileNotFoundError(f"Partial file not found: {part_path}")
    # os.replace provides atomic overwrite on both POSIX and Windows
    os.replace(part_path, dest_path)
