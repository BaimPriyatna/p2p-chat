"""
protocol.py — wire format shared by all peerc components.

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
MAX_CHAT_TEXT_SIZE = 64 * 1024  # 64 KB — a chat message is not a file (BUG-021)


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


def make_file_complete_ack(transfer_id: str, success: bool, detail: str = "") -> dict:
    """Sent by the receiver after it has verified the file (BUG-012).

    The sender should not consider a transfer "done" until this arrives —
    file_done only means "I sent all the bytes", not "you're happy with them".
    """
    return {
        "type": "file_complete_ack",
        "transfer_id": transfer_id,
        "success": success,
        "detail": detail,
    }


def make_error(code: str, message: str) -> dict:
    return {"type": "error", "code": code, "message": message}


# ---- Schema validation --------------------------------------------------
#
# read_message() only guarantees "valid JSON". It does NOT guarantee the
# result is a dict, has a "type", or carries the fields that type requires.
# validate_message() closes that gap (BUG-017 / BUG-018) so handlers can
# trust message["field"] instead of needing their own defensive code.

REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "chat": ("message_id", "sender_id", "sender_name", "text"),
    "chat_ack": ("message_id",),
    "file_offer": ("transfer_id", "filename", "size", "checksum"),
    "file_accept": ("transfer_id",),
    "file_reject": ("transfer_id",),
    "file_chunk": ("transfer_id", "chunk_index", "data", "is_last"),
    "file_done": ("transfer_id", "checksum"),
    "file_complete_ack": ("transfer_id", "success"),
    "hello": ("peer_id", "sender_name", "tcp_port"),
    "hello_ack": ("peer_id", "sender_name", "tcp_port"),
    "error": ("code", "message"),
}


def validate_message(message) -> dict:
    """Validate a decoded message against the wire schema.

    Raises ProtocolError (never KeyError/TypeError) if the message isn't a
    dict, has no recognized "type", or is missing fields that type requires.
    Returns the message unchanged on success, for convenient chaining.
    """
    if not isinstance(message, dict):
        raise ProtocolError(f"message is not an object: {type(message).__name__}")

    msg_type = message.get("type")
    if not isinstance(msg_type, str) or not msg_type:
        raise ProtocolError("message missing string 'type' field")

    required = REQUIRED_FIELDS.get(msg_type)
    if required is None:
        # Unknown type: let it through untyped-checked so the protocol can
        # still be extended/ignored gracefully by older peers.
        return message

    missing = [f for f in required if f not in message]
    if missing:
        raise ProtocolError(f"'{msg_type}' message missing fields: {missing}")

    if msg_type == "chat":
        if not isinstance(message["text"], str):
            raise ProtocolError("chat.text must be a string")
        if len(message["text"].encode("utf-8", errors="replace")) > MAX_CHAT_TEXT_SIZE:
            raise ProtocolError(f"chat.text exceeds {MAX_CHAT_TEXT_SIZE} bytes")

    if msg_type == "file_offer":
        if not isinstance(message["filename"], str) or not message["filename"]:
            raise ProtocolError("file_offer.filename must be a non-empty string")
        if not isinstance(message["size"], int) or message["size"] < 0:
            raise ProtocolError("file_offer.size must be a non-negative int")
        if not isinstance(message["checksum"], str) or not message["checksum"]:
            raise ProtocolError("file_offer.checksum must be a non-empty string")

    if msg_type == "file_chunk":
        if not isinstance(message["chunk_index"], int) or message["chunk_index"] < 0:
            raise ProtocolError("file_chunk.chunk_index must be a non-negative int")
        if not isinstance(message["data"], str):
            raise ProtocolError("file_chunk.data must be a base64 string")

    if msg_type == "hello" or msg_type == "hello_ack":
        port = message["tcp_port"]
        if not isinstance(port, int) or not (0 < port < 65536):
            raise ProtocolError(f"{msg_type}.tcp_port out of range: {port!r}")

    return message


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