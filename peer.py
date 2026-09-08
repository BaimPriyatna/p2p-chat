"""
peer.py — direct TCP connections between peers (transport layer).

Discovery (discovery.py) tells us WHO is out there and WHERE (ip:tcp_port).
This module handles actually connecting to them and exchanging framed
protocol messages (protocol.py) over TCP.

Design for Stage 2: a single ConnectionManager runs one TCP server (for
incoming connections) and can open outgoing connections to other peers.
Every open connection, incoming or outgoing, is treated identically once
established: read loop -> dispatch to on_message callback.
"""

import asyncio
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

import protocol

OnMessage = Callable[[str, dict], Awaitable[None]]  # (peer_addr_key, message) -> None


@dataclass
class Connection:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    addr_key: str  # "ip:port" of the remote end, used until we know its peer_id


class ConnectionManager:
    """Owns the TCP server and all active connections.

    Connections are keyed by "ip:port" string (addr_key) rather than
    peer_id, since at the raw TCP layer we don't know the peer_id until
    a message with sender_id arrives. Higher layers (Stage 3+) can map
    peer_id -> addr_key using the discovery peer list.
    """

    def __init__(self, listen_port: int, on_message: OnMessage):
        self.listen_port = listen_port
        self.on_message = on_message
        self._connections: dict[str, Connection] = {}
        self._server: Optional[asyncio.base_events.Server] = None

    async def start_server(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_incoming, host="0.0.0.0", port=self.listen_port
        )

    async def _handle_incoming(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer_addr = writer.get_extra_info("peername")
        addr_key = f"{peer_addr[0]}:{peer_addr[1]}"
        conn = Connection(reader, writer, addr_key)
        self._connections[addr_key] = conn
        await self._read_loop(conn)

    async def connect_to(self, ip: str, port: int) -> str:
        """Open an outgoing connection. Returns the addr_key for this connection."""
        addr_key = f"{ip}:{port}"
        if addr_key in self._connections:
            return addr_key

        reader, writer = await asyncio.open_connection(ip, port)
        conn = Connection(reader, writer, addr_key)
        self._connections[addr_key] = conn
        # Run the read loop in the background so this call returns immediately
        asyncio.create_task(self._read_loop(conn))
        return addr_key

    async def _read_loop(self, conn: Connection) -> None:
        try:
            while True:
                message = await protocol.read_message(conn.reader)
                await self.on_message(conn.addr_key, message)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass  # peer disconnected
        except protocol.ProtocolError:
            pass  # malformed frame — drop the connection rather than desync
        finally:
            self._connections.pop(conn.addr_key, None)
            conn.writer.close()

    async def send(self, addr_key: str, message: dict) -> bool:
        """Send a message on an already-open connection. Returns False if not connected."""
        conn = self._connections.get(addr_key)
        if conn is None:
            return False
        try:
            protocol.write_message(conn.writer, message)
            await conn.writer.drain()
            return True
        except (ConnectionResetError, BrokenPipeError):
            self._connections.pop(addr_key, None)
            return False

    def is_connected(self, addr_key: str) -> bool:
        return addr_key in self._connections

    async def close_all(self) -> None:
        for conn in list(self._connections.values()):
            conn.writer.close()
        self._connections.clear()
        if self._server:
            self._server.close()
            await self._server.wait_closed()


if __name__ == "__main__":
    # Manual test: run as either "server" or "client" role from two terminals.
    #   python3 peer.py server 5555
    #   python3 peer.py client 5555 <server-ip>
    import sys

    import discovery as _discovery  # reuse identity loader

    async def _main() -> None:
        role = sys.argv[1]
        port = int(sys.argv[2])
        peer_id, name = _discovery.load_or_create_identity()

        async def on_message(addr_key: str, message: dict) -> None:
            if message.get("type") == "chat":
                print(f"\n<{message['sender_name']}> {message['text']}")

        manager = ConnectionManager(listen_port=port, on_message=on_message)
        await manager.start_server()
        print(f"Listening on port {port} as {name} ({peer_id[:8]})")

        if role == "client":
            target_ip = sys.argv[3]
            addr_key = await manager.connect_to(target_ip, port)
            print(f"Connected to {addr_key}")

        # Simple stdin -> send loop for manual testing
        loop = asyncio.get_event_loop()
        while True:
            text = await loop.run_in_executor(None, input, "")
            if not manager._connections:
                print("(no connection yet)")
                continue
            msg = protocol.make_chat_message(peer_id, name, text)
            for addr_key in list(manager._connections.keys()):
                await manager.send(addr_key, msg)

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
