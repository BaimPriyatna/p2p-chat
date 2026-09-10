"""core/protocol/frame.py — wire framing shared by all peerc components.

Every message is a JSON object sent over TCP using length-prefix framing:

    [4 bytes: big-endian uint32 length][N bytes: UTF-8 JSON payload]

The length prefix lets a reader know exactly how many bytes to read for one
message, since TCP is a byte stream with no built-in message boundaries.

This module knows nothing about *what* a message means (that's
messages.py) — it only knows how to pack a dict into bytes and back.
"""

import asyncio
import json
import struct

from .errors import ProtocolError

LENGTH_PREFIX_FORMAT = ">I"  # big-endian unsigned 4-byte int
LENGTH_PREFIX_SIZE = struct.calcsize(LENGTH_PREFIX_FORMAT)
MAX_MESSAGE_SIZE = 100 * 1024 * 1024  # 100 MB safety cap for a single frame payload

# Phase 1.3: binary framing for file data (see core/protocol/binary.py).
#
# Rather than growing the header (which would be a hard break for anyone
# still reading the old [4-byte length][JSON] format), we steal the top bit
# of the length field as an is-binary flag. Real payloads are always well
# under 2 GB (MAX_MESSAGE_SIZE is 100 MB), so that bit is never legitimately
# set by a length value — using it as a flag costs nothing and changes
# nothing about the header's size.
BINARY_FLAG = 0x80000000


def encode_frame(message: dict) -> bytes:
    """Serialize a message dict into a length-prefixed JSON frame ready to send."""
    payload = json.dumps(message).encode("utf-8")
    if len(payload) > MAX_MESSAGE_SIZE:
        raise ProtocolError(f"message too large: {len(payload)} bytes")
    header = struct.pack(LENGTH_PREFIX_FORMAT, len(payload))
    return header + payload


def encode_binary_frame(payload: bytes) -> bytes:
    """Serialize a raw bytes payload into a length-prefixed binary frame.

    Used for file_data chunks (Phase 1.3) instead of base64-in-JSON — no
    ~33% base64 inflation, and no JSON parsing on the hot path.
    """
    if len(payload) > MAX_MESSAGE_SIZE:
        raise ProtocolError(f"binary payload too large: {len(payload)} bytes")
    header = struct.pack(LENGTH_PREFIX_FORMAT, len(payload) | BINARY_FLAG)
    return header + payload


async def read_frame(reader: asyncio.StreamReader) -> dict:
    """Read exactly one framed JSON message from an asyncio StreamReader.

    Raises asyncio.IncompleteReadError if the connection closes mid-frame
    (the caller should treat this as a disconnect), or ProtocolError if the
    frame is malformed, oversized, or turns out to be a binary frame (use
    read_any_frame() if the caller needs to accept both kinds).
    """
    kind, payload = await _read_raw(reader)
    if kind != "json":
        raise ProtocolError("expected a JSON frame but got a binary frame")
    return _decode_json(payload)


async def read_any_frame(reader: asyncio.StreamReader) -> tuple:
    """Read one frame of either kind.

    Returns ("json", dict) or ("binary", bytes). Use this in a read loop
    that needs to accept both control messages and file_data chunks on the
    same connection.
    """
    kind, payload = await _read_raw(reader)
    if kind == "json":
        return "json", _decode_json(payload)
    return "binary", payload


async def _read_raw(reader: asyncio.StreamReader) -> tuple:
    header = await reader.readexactly(LENGTH_PREFIX_SIZE)
    (raw_length,) = struct.unpack(LENGTH_PREFIX_FORMAT, header)

    is_binary = bool(raw_length & BINARY_FLAG)
    length = raw_length & ~BINARY_FLAG

    if length == 0 or length > MAX_MESSAGE_SIZE:
        raise ProtocolError(f"invalid frame length: {length}")

    payload = await reader.readexactly(length)
    return ("binary" if is_binary else "json"), payload


def _decode_json(payload: bytes) -> dict:
    try:
        return json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ProtocolError(f"malformed JSON payload: {e}") from e


def write_frame(writer: asyncio.StreamWriter, message: dict) -> None:
    """Queue a framed JSON message for sending. Caller should await writer.drain()."""
    writer.write(encode_frame(message))


def write_binary_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    """Queue a framed binary payload for sending. Caller should await writer.drain()."""
    writer.write(encode_binary_frame(payload))
