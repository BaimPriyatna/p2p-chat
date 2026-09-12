"""core/transfer/sender.py — Outbound file sender state machine (Phases 12, 16, 19).

Streams binary file_data chunks, supports offset resume seeking, and handles
the authoritative complete acknowledgement handshake.
"""

import asyncio
import os
from typing import Generator, Optional, Tuple

from .chunker import DEFAULT_CHUNK_SIZE, read_chunks
from .hashing import sha256_file

COMPLETE_ACK_TIMEOUT = 30.0  # seconds sender waits for receiver's verification


class FileSender:
    """Manages chunk generation, progress tracking, and acknowledgement for an outgoing transfer."""

    def __init__(
        self,
        transfer_id: str,
        filepath: str,
        filename: Optional[str] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        self.transfer_id = transfer_id
        self.filepath = filepath
        self.filename = filename or os.path.basename(filepath)
        self.size = os.path.getsize(filepath)
        self.checksum = sha256_file(filepath)
        self.chunk_size = chunk_size

        self.bytes_sent = 0
        self.status = "offered"  # offered -> sending -> awaiting_ack -> done / failed
        self._ack_event = asyncio.Event()
        self._ack_success = False
        self._ack_reason = ""

    def get_chunks(self, start_offset: int = 0) -> Generator[Tuple[int, int, bytes], None, None]:
        """Generate (sequence, offset, chunk_bytes) beginning from start_offset."""
        self.status = "sending"
        self.bytes_sent = start_offset
        for seq, offset, data in read_chunks(self.filepath, start_offset, self.chunk_size):
            yield seq, offset, data
            self.bytes_sent += len(data)

    def mark_ack(self, success: bool, reason: str = "") -> None:
        """Record the file_complete_ack response from the receiver."""
        self._ack_success = success
        self._ack_reason = reason
        self._ack_event.set()

    async def wait_for_ack(self, timeout: float = COMPLETE_ACK_TIMEOUT) -> bool:
        """Wait for the receiver's verification ack with timeout."""
        self.status = "awaiting_ack"
        try:
            await asyncio.wait_for(self._ack_event.wait(), timeout=timeout)
            self.status = "done" if self._ack_success else "failed"
            return self._ack_success
        except asyncio.TimeoutError:
            self.status = "failed"
            self._ack_reason = "ack timed out"
            return False
