"""core/transport/tcp.py — Raw TCP transport abstraction (Phase 9).

Encapsulates low-level asyncio TCP StreamReader/StreamWriter streams, providing
safe lifecycle management, length-prefixed framing, and timeout guards.
"""

import asyncio
from typing import Optional, Tuple

from core.protocol.frame import (
    encode_binary_frame,
    encode_frame,
    read_any_frame,
    write_binary_frame,
    write_frame,
)
from .timeout import (
    CONNECT_TIMEOUT,
    ConnectionClosedError,
    ConnectTimeoutError,
    TransportError,
)


class TCPConnection:
    """Encapsulates an established TCP connection with its reader and writer streams."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self._closed = False

        peer_info = writer.get_extra_info("peername")
        if peer_info:
            self._peer_ip = str(peer_info[0])
            self._peer_port = int(peer_info[1])
        else:
            self._peer_ip = "0.0.0.0"
            self._peer_port = 0

    @property
    def peer_addr(self) -> Tuple[str, int]:
        """Returns (ip, port) tuple of the remote peer."""
        return self._peer_ip, self._peer_port

    @property
    def addr_key(self) -> str:
        """Returns standard 'ip:port' string identifier."""
        return f"{self._peer_ip}:{self._peer_port}"

    @property
    def is_closing(self) -> bool:
        """True if the connection has been marked for closure or is closed."""
        return self._closed or self.writer.is_closing()

    async def read_frame(self) -> Tuple[str, object]:
        """Read one length-prefixed frame of either kind.

        Returns:
            ("json", dict) for control frames or ("binary", bytes) for binary frames.

        Raises:
            ConnectionClosedError: If peer disconnected or stream reached EOF.
            TransportError: If frame framing or payload parsing failed.
        """
        if self.is_closing:
            raise ConnectionClosedError("Cannot read from closed TCP connection")

        try:
            return await read_any_frame(self.reader)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError) as e:
            self._closed = True
            raise ConnectionClosedError(f"Connection closed by peer: {e}") from e
        except Exception as e:
            raise TransportError(f"TCP frame read error: {e}") from e

    async def write_frame(self, message: dict) -> None:
        """Send a length-prefixed JSON message frame and drain buffer."""
        if self.is_closing:
            raise ConnectionClosedError("Cannot write to closed TCP connection")

        try:
            write_frame(self.writer, message)
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            self._closed = True
            raise ConnectionClosedError(f"Connection lost while writing frame: {e}") from e
        except Exception as e:
            raise TransportError(f"TCP frame write error: {e}") from e

    async def write_binary_frame(self, payload: bytes) -> None:
        """Send a length-prefixed binary frame and drain buffer."""
        if self.is_closing:
            raise ConnectionClosedError("Cannot write to closed TCP connection")

        try:
            write_binary_frame(self.writer, payload)
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            self._closed = True
            raise ConnectionClosedError(f"Connection lost while writing binary frame: {e}") from e
        except Exception as e:
            raise TransportError(f"TCP binary frame write error: {e}") from e

    async def close(self) -> None:
        """Gracefully close the TCP socket."""
        if self._closed:
            return
        self._closed = True
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except (OSError, asyncio.CancelledError):
            pass

    def __repr__(self) -> str:
        status = "closed" if self.is_closing else "open"
        return f"<TCPConnection {self.addr_key} ({status})>"


async def open_tcp_connection(
    host: str,
    port: int,
    timeout: float = CONNECT_TIMEOUT,
) -> TCPConnection:
    """Connect to a remote TCP endpoint with a strict timeout guard.

    Args:
        host: Remote hostname or IP address.
        port: Remote TCP port number.
        timeout: Maximum seconds to wait for connection completion.

    Returns:
        Connected TCPConnection instance.

    Raises:
        ConnectTimeoutError: If the TCP connection could not be established within timeout.
        TransportError: If connection was refused or network error occurred.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        return TCPConnection(reader, writer)
    except asyncio.TimeoutError as e:
        raise ConnectTimeoutError(
            f"Timed out connecting to {host}:{port} after {timeout}s"
        ) from e
    except Exception as e:
        raise TransportError(f"Failed to connect to {host}:{port}: {e}") from e
