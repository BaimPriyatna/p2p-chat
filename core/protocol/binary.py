"""core/protocol/binary.py — wire layout for file_data binary frames.

Phase 1.3 replaces the old base64-in-JSON `file_chunk` message with a raw
binary frame for the actual file bytes. Control messages (file_offer,
file_accept, file_reject, file_done, file_complete_ack) stay as JSON —
only the high-frequency, high-volume chunk data moves to binary, since
that's where the ~33% base64 overhead and JSON parsing cost actually add
up over a large transfer.

Layout of a file_data binary frame's payload (all integers big-endian):

    [16 bytes] transfer_id   — UUID.bytes (NOT the 36-char string form)
    [4 bytes]  sequence      — uint32, 0-based chunk index
    [8 bytes]  offset        — uint64, byte offset of this chunk in the file
    [remainder] data         — raw chunk bytes

Fixed 28-byte header regardless of chunk size, vs. base64's ~33% inflation
of the chunk itself plus JSON framing (field names, quotes, escaping) on
top of that.
"""

import struct
import uuid

from .errors import ProtocolError

_HEADER_FORMAT = ">16sIQ"  # transfer_id bytes, sequence uint32, offset uint64
_HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)


def encode_file_data(transfer_id: str, sequence: int, offset: int, data: bytes) -> bytes:
    """Pack a file chunk into the binary frame payload described above."""
    try:
        tid_bytes = uuid.UUID(transfer_id).bytes
    except ValueError as e:
        raise ProtocolError(f"transfer_id is not a valid UUID: {transfer_id!r}") from e
    if sequence < 0 or sequence > 0xFFFFFFFF:
        raise ProtocolError(f"sequence out of range for uint32: {sequence}")
    if offset < 0 or offset > 0xFFFFFFFFFFFFFFFF:
        raise ProtocolError(f"offset out of range for uint64: {offset}")
    header = struct.pack(_HEADER_FORMAT, tid_bytes, sequence, offset)
    return header + data


def decode_file_data(payload: bytes) -> dict:
    """Unpack a file_data binary frame payload into its fields.

    Returns {"transfer_id": str, "sequence": int, "offset": int, "data": bytes}.
    Raises ProtocolError if the payload is too short to even contain a header
    — this is the binary-frame equivalent of validate_message()'s missing-
    field check, since a hostile peer can send an arbitrarily short binary
    frame just as easily as a malformed JSON one.
    """
    if len(payload) < _HEADER_SIZE:
        raise ProtocolError(
            f"file_data frame too short: {len(payload)} bytes, need at least {_HEADER_SIZE}"
        )
    tid_bytes, sequence, offset = struct.unpack(_HEADER_FORMAT, payload[:_HEADER_SIZE])
    return {
        "transfer_id": str(uuid.UUID(bytes=tid_bytes)),
        "sequence": sequence,
        "offset": offset,
        "data": payload[_HEADER_SIZE:],
    }
