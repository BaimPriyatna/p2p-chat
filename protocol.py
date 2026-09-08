"""
protocol.py — wire format shared by all p2p-chat components.

Every message is a JSON object sent over TCP using length-prefix framing:

    [4 bytes: big-endian uint32 length][N bytes: UTF-8 JSON payload]

The length prefix lets a reader know exactly how many bytes to read for one
message, since TCP is a byte stream with no built-in message boundaries.

Message types (more added in later stages):
    chat        - a plain text chat message
    chat_ack    - acknowledges receipt of a chat message (added Stage 3)
    file_offer  - proposes a file transfer (added Stage 4)
    file_accept - accepts a pending file offer (added Stage 4)
    file_reject - rejects a pending file offer (added Stage 4)
    file_chunk  - one chunk of file data (added Stage 4)
    file_done   - signals file transfer complete + checksum (added Stage 4)
"""

import asyncio
import json
import struct
import time
import uuid

LENGTH_PREFIX_FORMAT = ">I"  # big-endian unsigned 4-byte int
LENGTH_PREFIX_SIZE = struct.calcsize(LENGTH_PREFIX_FORMAT)
MAX_MESSAGE_SIZE = 100 * 1024 * 1024  # 100 MB safety cap


class ProtocolError(Exception):
    """Raised on malformed frames or messages that violate the wire format."""


def new_message_id() -> str:
    return str(uuid.uuid4())


def make_chat_message(sender_id: str, sender_name: str, text: str) -> dict:
    return {
        "type": "chat",
        "message_id": new_message_id(),
        "sender_id": sender_id,
        "sender_name": sender_name,
        "text": text,
        "timestamp": time.time(),
    }


def make_chat_ack(message_id: str) -> dict:
    """Sent back by the receiver to confirm a chat message arrived intact."""
    return {
        "type": "chat_ack",
        "message_id": message_id,
        "timestamp": time.time(),
    }


def make_file_offer(
    transfer_id: str, sender_id: str, sender_name: str,
    filename: str, size: int, checksum: str,
) -> dict:
    return {
        "type": "file_offer",
        "transfer_id": transfer_id,
        "sender_id": sender_id,
        "sender_name": sender_name,
        "filename": filename,
        "size": size,
        "checksum": checksum,
        "timestamp": time.time(),
    }


def make_file_accept(transfer_id: str) -> dict:
    return {"type": "file_accept", "transfer_id": transfer_id, "timestamp": time.time()}


def make_file_reject(transfer_id: str) -> dict:
    return {"type": "file_reject", "transfer_id": transfer_id, "timestamp": time.time()}


def make_file_chunk(transfer_id: str, chunk_index: int, data_b64: str, is_last: bool) -> dict:
    return {
        "type": "file_chunk",
        "transfer_id": transfer_id,
        "chunk_index": chunk_index,
        "data": data_b64,
        "is_last": is_last,
    }


def make_file_done(transfer_id: str, checksum: str) -> dict:
    return {"type": "file_done", "transfer_id": transfer_id, "checksum": checksum}


def make_hello(peer_id: str, sender_name: str, tcp_port: int) -> dict:
    return {
        "type": "hello",
        "peer_id": peer_id,
        "sender_name": sender_name,
        "tcp_port": tcp_port,
        "timestamp": time.time(),
    }


def make_hello_ack(peer_id: str, sender_name: str, tcp_port: int) -> dict:
    return {
        "type": "hello_ack",
        "peer_id": peer_id,
        "sender_name": sender_name,
        "tcp_port": tcp_port,
        "timestamp": time.time(),
    }


def encode_message(message: dict) -> bytes:
    """Serialize a message dict into a length-prefixed frame ready to send."""
    payload = json.dumps(message).encode("utf-8")
    if len(payload) > MAX_MESSAGE_SIZE:
        raise ProtocolError(f"message too large: {len(payload)} bytes")
    header = struct.pack(LENGTH_PREFIX_FORMAT, len(payload))
    return header + payload


async def read_message(reader: asyncio.StreamReader) -> dict:
    """Read exactly one framed message from an asyncio StreamReader.

    Raises asyncio.IncompleteReadError if the connection closes mid-frame
    (the caller should treat this as a disconnect), or ProtocolError if the
    declared length is unreasonable.
    """
    header = await reader.readexactly(LENGTH_PREFIX_SIZE)
    (length,) = struct.unpack(LENGTH_PREFIX_FORMAT, header)

    if length == 0 or length > MAX_MESSAGE_SIZE:
        raise ProtocolError(f"invalid frame length: {length}")

    payload = await reader.readexactly(length)
    try:
        return json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ProtocolError(f"malformed JSON payload: {e}") from e


def write_message(writer: asyncio.StreamWriter, message: dict) -> None:
    """Queue a framed message for sending. Caller should await writer.drain()."""
    writer.write(encode_message(message))
