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
MAX_INCOMING_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB safety cap (BUG-002)
COMPLETE_ACK_TIMEOUT = 30.0  # seconds sender waits for receiver's verification (BUG-012)


class PathTraversalError(Exception):
    """Raised when a remote-supplied filename would escape downloads_dir."""

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
    status: str = "offered"  # offered -> accepted/rejected -> sending -> awaiting_ack -> done/failed
    _ack_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    _ack_success: bool = field(default=False, repr=False)


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
    expected_chunk_index: int = 0
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
            "file_complete_ack": self._handle_complete_ack,
        }
        handler = handlers.get(msg_type)
        if handler:
            await handler(addr_key, message)
        elif self._next_on_message:
            await self._next_on_message(addr_key, message)

    # ---- Sender side -------------------------------------------------

    async def offer_file(self, addr_key: str, filepath: str) -> Optional[str]:
        """Announce a file transfer to a connected peer.

        Returns the transfer_id, or None if the peer isn't actually
        connected (BUG-013) — callers should treat None as "not sent".
        """
        size = os.path.getsize(filepath)
        checksum = _sha256_file(filepath)
        filename = os.path.basename(filepath)
        transfer_id = str(uuid.uuid4())

        transfer = OutgoingTransfer(
            transfer_id=transfer_id, addr_key=addr_key, filepath=filepath,
            filename=filename, size=size, checksum=checksum,
        )

        offer = protocol.make_file_offer(
            transfer_id, sender_id="", sender_name="", filename=filename,
            size=size, checksum=checksum,
        )
        ok = await self.manager.send(addr_key, offer)
        if not ok:
            # Connection isn't there — don't pretend we offered anything.
            return None

        self._outgoing[transfer_id] = transfer
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
            transfer.status = "awaiting_ack"

            # Don't declare victory just because we finished sending bytes
            # (BUG-012) — wait for the receiver to verify the checksum.
            try:
                await asyncio.wait_for(transfer._ack_event.wait(), COMPLETE_ACK_TIMEOUT)
                success = transfer._ack_success
            except asyncio.TimeoutError:
                success = False

            transfer.status = "done" if success else "failed"
            if self.on_complete:
                self.on_complete(transfer.transfer_id, success, transfer.filepath if success else None)
        except OSError:
            transfer.status = "failed"
            if self.on_complete:
                self.on_complete(transfer.transfer_id, False, None)
        finally:
            self._outgoing.pop(transfer.transfer_id, None)

    async def _handle_complete_ack(self, addr_key: str, message: dict) -> None:
        transfer = self._outgoing.get(message["transfer_id"])
        if transfer is None:
            return
        transfer._ack_success = bool(message.get("success"))
        transfer._ack_event.set()

    # ---- Receiver side -------------------------------------------------

    async def _handle_offer(self, addr_key: str, message: dict) -> None:
        transfer_id = message["transfer_id"]
        filename = message["filename"]
        size = message["size"]
        checksum = message["checksum"]
        sender_name = message.get("sender_name") or "peer"

        # BUG-002: reject oversized offers before ever asking the user.
        if size > MAX_INCOMING_FILE_SIZE:
            await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
            return

        # BUG-001: resolve the destination now, before we even ask the user,
        # so a hostile filename can't get anywhere near the filesystem.
        try:
            dest_path = self._safe_dest_path(filename)
        except PathTraversalError:
            await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
            return

        accept = True
        if self.on_offer_received:
            accept = await self.on_offer_received(transfer_id, filename, size, sender_name)

        if not accept:
            await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
            return

        incoming = IncomingTransfer(
            transfer_id=transfer_id, addr_key=addr_key, filename=filename,
            size=size, expected_checksum=checksum, sender_name=sender_name,
            dest_path=dest_path,
        )
        incoming._file_handle = open(dest_path, "wb")
        self._incoming[transfer_id] = incoming

        await self.manager.send(addr_key, protocol.make_file_accept(transfer_id))

    def _safe_dest_path(self, filename: str) -> str:
        """Turn a remote-supplied filename into a safe path inside downloads_dir.

        Defends against path traversal (BUG-001): "../../important.txt",
        absolute paths like "/etc/passwd", and any symlink tricks, by
        stripping to a bare basename and then verifying the resolved
        destination is still actually inside downloads_dir.
        """
        # basename() alone isn't enough on its own (e.g. it won't stop a
        # crafted absolute path on some platforms), so we also resolve and
        # re-check containment below.
        name = os.path.basename(filename.replace("\\", "/"))
        name = name.strip()
        if not name or name in (".", ".."):
            raise PathTraversalError(f"unsafe filename: {filename!r}")

        downloads_root = os.path.realpath(self.downloads_dir)
        candidate = self._unique_dest_path(name)
        resolved = os.path.realpath(candidate)

        if os.path.commonpath([resolved, downloads_root]) != downloads_root:
            raise PathTraversalError(f"resolved path escapes downloads_dir: {resolved!r}")

        return candidate

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

        # BUG-008: reject out-of-order chunks rather than silently
        # concatenating whatever arrives.
        chunk_index = message["chunk_index"]
        if chunk_index != transfer.expected_chunk_index:
            await self._abort_incoming(transfer, "out-of-order chunk")
            return

        data = base64.b64decode(message["data"])

        # BUG-002: enforce the size the sender declared in file_offer —
        # never let actual bytes on disk exceed it.
        if transfer.bytes_received + len(data) > transfer.size:
            await self._abort_incoming(transfer, "declared size exceeded")
            return

        transfer._file_handle.write(data)
        transfer.bytes_received += len(data)
        transfer.expected_chunk_index += 1

        # BUG-009: is_last should actually mean something — a peer claiming
        # "last chunk" without having sent all declared bytes is lying.
        is_last = bool(message.get("is_last"))
        if is_last and transfer.bytes_received != transfer.size:
            await self._abort_incoming(transfer, "is_last with incomplete bytes")
            return

        if self.on_progress:
            self.on_progress(transfer.transfer_id, transfer.bytes_received, transfer.size)

    async def _abort_incoming(self, transfer: "IncomingTransfer", reason: str) -> None:
        self._incoming.pop(transfer.transfer_id, None)
        if transfer._file_handle:
            transfer._file_handle.close()
        if os.path.exists(transfer.dest_path):
            os.remove(transfer.dest_path)
        transfer.status = "failed"
        await self.manager.send(
            transfer.addr_key,
            protocol.make_file_complete_ack(transfer.transfer_id, False, reason),
        )
        if self.on_complete:
            self.on_complete(transfer.transfer_id, False, None)

    async def _handle_done(self, addr_key: str, message: dict) -> None:
        transfer = self._incoming.pop(message["transfer_id"], None)
        if transfer is None:
            return
        transfer._file_handle.close()

        # BUG-010: the checksum from file_offer is authoritative. file_done's
        # checksum field is NOT trusted to override it — otherwise a sender
        # could ship bad bytes and then simply declare them "correct".
        actual_checksum = _sha256_file(transfer.dest_path)
        expected_checksum = transfer.expected_checksum
        success = actual_checksum == expected_checksum and transfer.bytes_received == transfer.size

        detail = "" if success else "checksum mismatch"
        await self.manager.send(
            addr_key, protocol.make_file_complete_ack(transfer.transfer_id, success, detail)
        )

        if not success:
            transfer.status = "failed"
            os.remove(transfer.dest_path)
            if self.on_complete:
                self.on_complete(transfer.transfer_id, False, None)
            return

        transfer.status = "done"
        if self.on_complete:
            self.on_complete(transfer.transfer_id, True, transfer.dest_path)