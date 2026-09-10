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
MAX_MESSAGE_SIZE = 100 * 1024 * 1024  # 100 MB safety cap for the JSON control frame


def encode_frame(message: dict) -> bytes:
    """Serialize a message dict into a length-prefixed frame ready to send."""
    payload = json.dumps(message).encode("utf-8")
    if len(payload) > MAX_MESSAGE_SIZE:
        raise ProtocolError(f"message too large: {len(payload)} bytes")
    header = struct.pack(LENGTH_PREFIX_FORMAT, len(payload))
    return header + payload


async def read_frame(reader: asyncio.StreamReader) -> dict:
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


def write_frame(writer: asyncio.StreamWriter, message: dict) -> None:
    """Queue a framed message for sending. Caller should await writer.drain()."""
    writer.write(encode_frame(message))
