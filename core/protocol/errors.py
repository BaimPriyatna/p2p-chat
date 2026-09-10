"""core/protocol/errors.py — exceptions raised by the protocol layer.

Kept in its own module (no dependency on frame.py or messages.py) so any
part of the codebase can catch ProtocolError without pulling in framing or
message-construction code.
"""


class ProtocolError(Exception):
    """Raised on malformed frames or messages that violate the wire format."""
