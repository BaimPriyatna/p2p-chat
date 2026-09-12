"""core/transport/timeout.py — Standard transport timeouts and exceptions (Phase 9).

Centralizes network timeout constants and transport-level exception types per
IMPLEMENTATION_PLAN.md lines 693-707.
"""

CONNECT_TIMEOUT = 5.0      # Maximum seconds to wait for initial TCP connection establishment
HANDSHAKE_TIMEOUT = 5.0    # Maximum seconds to wait for 3-way authenticated handshake completion
IDLE_TIMEOUT = 60.0        # Maximum seconds of inactivity before considering an idle connection stale
DEFAULT_READ_TIMEOUT = 30.0  # Default timeout for stream read operations when applicable


class TransportError(Exception):
    """Base exception for all transport-level errors."""


class TransportTimeoutError(TransportError):
    """Raised when a transport operation exceeds its configured deadline."""


class ConnectTimeoutError(TransportTimeoutError):
    """Raised when establishing an outgoing TCP connection times out."""


class HandshakeTimeoutError(TransportTimeoutError):
    """Raised when the mutual cryptographic handshake times out."""


class IdleTimeoutError(TransportTimeoutError):
    """Raised when a connection remains inactive past the idle limit."""


class ConnectionClosedError(TransportError):
    """Raised when attempting an operation on a closed or disconnected transport."""
