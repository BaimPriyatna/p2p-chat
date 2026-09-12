"""core/transfer/chunker.py — File chunking and streaming generators (Phase 12).

Splits files into uniform binary chunks suitable for network transmission, with
offset seeking to support resumable transfers.
"""

import os
from typing import Generator, Tuple

DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB per chunk


def read_chunks(
    filepath: str,
    start_offset: int = 0,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Generator[Tuple[int, int, bytes], None, None]:
    """Yields (sequence_index, byte_offset, chunk_bytes) starting from start_offset.

    Args:
        filepath: Local file path to read from.
        start_offset: Byte position to seek before reading (used for resume).
        chunk_size: Size of each binary chunk.

    Yields:
        Tuple of (sequence_index, byte_offset, chunk_bytes).
    """
    total_size = os.path.getsize(filepath)
    if start_offset > total_size:
        raise ValueError(f"start_offset {start_offset} exceeds file size {total_size}")

    with open(filepath, "rb") as f:
        if start_offset > 0:
            f.seek(start_offset)

        current_offset = start_offset
        sequence_index = start_offset // chunk_size

        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield sequence_index, current_offset, chunk
            current_offset += len(chunk)
            sequence_index += 1
