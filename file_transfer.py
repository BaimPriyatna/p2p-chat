"""
file_transfer.py — staged file transfer: offer -> accept/reject -> chunks -> done.

Follows the same wrapping pattern as chat.ChatSession so multiple sessions
can be layered on one ConnectionManager: each session wraps
manager.on_message, handles the message types it owns, and passes anything
else down the chain to whatever was set before it.

Wire flow:
    sender                              receiver
    ------                              --------
    file_offer  ------------------->    (asks on_offer_received callback)
                <-----------------      file_accept  (or file_reject, and stop)
    file_chunk (N times) ----------->   (writes bytes to disk incrementally)
    file_done (with checksum) ----->    (verifies checksum, calls on_complete)

Chunks are base64-encoded inside the existing JSON frame format for
simplicity/consistency with the rest of the protocol. This has real
overhead (~33%) — acceptable for Stage 4; noted in README Known Limitations.
"""

import asyncio
import base64
import hashlib
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

import protocol
from peer import ConnectionManager

CHUNK_SIZE = 64 * 1024  # 64 KB per chunk

# (transfer_id, filename, size, sender_name) -> bool (accept?)
OnOfferReceived = Callable[[str, str, int, str], Awaitable[bool]]
# (transfer_id, bytes_done, total_bytes) -> None
OnProgress = Callable[[str, int, int], None]
# (transfer_id, success, filepath_or_none) -> None
OnComplete = Callable[[str, bool, Optional[str]], None]


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class OutgoingTransfer:
    transfer_id: str
    addr_key: str
    filepath: str
    filename: str
    size: int
    checksum: str
    status: str = "offered"  # offered -> accepted/rejected -> sending -> done/failed


@dataclass
class IncomingTransfer:
    transfer_id: str
    addr_key: str
    filename: str
    size: int
    expected_checksum: str
    sender_name: str
    dest_path: str
    bytes_received: int = 0
    status: str = "offered"
    _file_handle: object = field(default=None, repr=False)


class FileTransferSession:
    def __init__(
        self,
        manager: ConnectionManager,
        downloads_dir: str = "downloads",
        on_offer_received: Optional[OnOfferReceived] = None,
        on_progress: Optional[OnProgress] = None,
        on_complete: Optional[OnComplete] = None,
    ):
        self.manager = manager
        self.downloads_dir = downloads_dir
        self.on_offer_received = on_offer_received
        self.on_progress = on_progress
        self.on_complete = on_complete

        os.makedirs(downloads_dir, exist_ok=True)

        self._outgoing: dict[str, OutgoingTransfer] = {}
        self._incoming: dict[str, IncomingTransfer] = {}

        # Chain onto whatever dispatcher is already set (e.g. ChatSession's).
        self._next_on_message = manager.on_message
        manager.on_message = self._dispatch

    async def _dispatch(self, addr_key: str, message: dict) -> None:
        msg_type = message.get("type")
        handlers = {
            "file_offer": self._handle_offer,
            "file_accept": self._handle_accept,
            "file_reject": self._handle_reject,
            "file_chunk": self._handle_chunk,
            "file_done": self._handle_done,
        }
        handler = handlers.get(msg_type)
        if handler:
            await handler(addr_key, message)
        elif self._next_on_message:
            await self._next_on_message(addr_key, message)

    # ---- Sender side -------------------------------------------------

    async def offer_file(self, addr_key: str, filepath: str) -> str:
        """Announce a file transfer to a connected peer. Returns transfer_id."""
        size = os.path.getsize(filepath)
        checksum = _sha256_file(filepath)
        filename = os.path.basename(filepath)
        transfer_id = str(uuid.uuid4())

        transfer = OutgoingTransfer(
            transfer_id=transfer_id, addr_key=addr_key, filepath=filepath,
            filename=filename, size=size, checksum=checksum,
        )
        self._outgoing[transfer_id] = transfer

        offer = protocol.make_file_offer(
            transfer_id, sender_id="", sender_name="", filename=filename,
            size=size, checksum=checksum,
        )
        await self.manager.send(addr_key, offer)
        return transfer_id

    async def _handle_accept(self, addr_key: str, message: dict) -> None:
        transfer = self._outgoing.get(message["transfer_id"])
        if transfer is None:
            return
        transfer.status = "sending"
        asyncio.create_task(self._send_chunks(transfer))

    async def _handle_reject(self, addr_key: str, message: dict) -> None:
        transfer = self._outgoing.get(message["transfer_id"])
        if transfer is None:
            return
        transfer.status = "rejected"
        if self.on_complete:
            self.on_complete(transfer.transfer_id, False, None)
        self._outgoing.pop(transfer.transfer_id, None)

    async def _send_chunks(self, transfer: OutgoingTransfer) -> None:
        bytes_sent = 0
        try:
            with open(transfer.filepath, "rb") as f:
                index = 0
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    bytes_sent += len(chunk)
                    is_last = bytes_sent >= transfer.size
                    msg = protocol.make_file_chunk(
                        transfer.transfer_id, index, base64.b64encode(chunk).decode("ascii"), is_last,
                    )
                    ok = await self.manager.send(transfer.addr_key, msg)
                    if not ok:
                        transfer.status = "failed"
                        if self.on_complete:
                            self.on_complete(transfer.transfer_id, False, None)
                        return
                    if self.on_progress:
                        self.on_progress(transfer.transfer_id, bytes_sent, transfer.size)
                    index += 1

            done = protocol.make_file_done(transfer.transfer_id, transfer.checksum)
            await self.manager.send(transfer.addr_key, done)
            transfer.status = "done"
        except OSError:
            transfer.status = "failed"
            if self.on_complete:
                self.on_complete(transfer.transfer_id, False, None)
        finally:
            self._outgoing.pop(transfer.transfer_id, None)

    # ---- Receiver side -------------------------------------------------

    async def _handle_offer(self, addr_key: str, message: dict) -> None:
        transfer_id = message["transfer_id"]
        filename = message["filename"]
        size = message["size"]
        checksum = message["checksum"]
        sender_name = message.get("sender_name") or "peer"

        accept = True
        if self.on_offer_received:
            accept = await self.on_offer_received(transfer_id, filename, size, sender_name)

        if not accept:
            await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
            return

        dest_path = self._unique_dest_path(filename)
        incoming = IncomingTransfer(
            transfer_id=transfer_id, addr_key=addr_key, filename=filename,
            size=size, expected_checksum=checksum, sender_name=sender_name,
            dest_path=dest_path,
        )
        incoming._file_handle = open(dest_path, "wb")
        self._incoming[transfer_id] = incoming

        await self.manager.send(addr_key, protocol.make_file_accept(transfer_id))

    def _unique_dest_path(self, filename: str) -> str:
        base, ext = os.path.splitext(filename)
        candidate = os.path.join(self.downloads_dir, filename)
        counter = 1
        while os.path.exists(candidate):
            candidate = os.path.join(self.downloads_dir, f"{base} ({counter}){ext}")
            counter += 1
        return candidate

    async def _handle_chunk(self, addr_key: str, message: dict) -> None:
        transfer = self._incoming.get(message["transfer_id"])
        if transfer is None:
            return
        data = base64.b64decode(message["data"])
        transfer._file_handle.write(data)
        transfer.bytes_received += len(data)
        if self.on_progress:
            self.on_progress(transfer.transfer_id, transfer.bytes_received, transfer.size)

    async def _handle_done(self, addr_key: str, message: dict) -> None:
        transfer = self._incoming.pop(message["transfer_id"], None)
        if transfer is None:
            return
        transfer._file_handle.close()

        actual_checksum = _sha256_file(transfer.dest_path)
        expected_checksum = message.get("checksum") or transfer.expected_checksum
        success = actual_checksum == expected_checksum

        if not success:
            transfer.status = "failed"
            os.remove(transfer.dest_path)
            if self.on_complete:
                self.on_complete(transfer.transfer_id, False, None)
            return

        transfer.status = "done"
        if self.on_complete:
            self.on_complete(transfer.transfer_id, True, transfer.dest_path)
