"""
discovery.py — MNDP-style peer discovery via UDP broadcast.

Each running instance periodically broadcasts a JSON "announce" packet
containing its stable peer_id, display name, and TCP port. Other instances
listen for these broadcasts and maintain a live peer list, evicting peers
that haven't announced within PEER_TIMEOUT seconds (handles DHCP IP changes
and peers going offline).
"""

import asyncio
import json
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

BROADCAST_PORT = 9999
ANNOUNCE_INTERVAL = 3.0   # seconds between announces
PEER_TIMEOUT = 10.0       # seconds of silence before a peer is considered offline


@dataclass
class Peer:
    peer_id: str
    name: str
    ip: str
    tcp_port: int
    last_seen: float = field(default_factory=time.time)


class PeerRegistry:
    """Thread/async-safe-enough store of currently known peers.

    Keyed by peer_id (NOT ip), since IP can change under DHCP or when
    switching between LAN and hotspot.
    """

    def __init__(self, on_peer_new: Optional[Callable[[Peer], None]] = None,
                 on_peer_lost: Optional[Callable[[Peer], None]] = None):
        self._peers: dict[str, Peer] = {}
        self._on_peer_new = on_peer_new
        self._on_peer_lost = on_peer_lost

    def upsert(self, peer_id: str, name: str, ip: str, tcp_port: int) -> None:
        existing = self._peers.get(peer_id)
        now = time.time()
        if existing is None:
            self._peers[peer_id] = Peer(peer_id, name, ip, tcp_port, now)
            if self._on_peer_new:
                self._on_peer_new(self._peers[peer_id])
        else:
            # Update in place — IP/port may have changed (DHCP renew, network switch)
            existing.name = name
            existing.ip = ip
            existing.tcp_port = tcp_port
            existing.last_seen = now

    def prune_stale(self) -> None:
        now = time.time()
        stale_ids = [
            pid for pid, p in self._peers.items()
            if now - p.last_seen > PEER_TIMEOUT
        ]
        for pid in stale_ids:
            peer = self._peers.pop(pid)
            if self._on_peer_lost:
                self._on_peer_lost(peer)

    def list_peers(self) -> list[Peer]:
        return list(self._peers.values())

    def get(self, peer_id: str) -> Optional[Peer]:
        return self._peers.get(peer_id)


def load_or_create_identity(config_path: str = ".p2pchat_identity.json") -> tuple[str, str]:
    """Return (peer_id, name), generating and persisting a UUID on first run.

    A stable peer_id is essential: it lets other peers recognize "this is
    still the same node" even after its IP address changes.
    """
    import os

    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            data = json.load(f)
        return data["peer_id"], data["name"]

    peer_id = str(uuid.uuid4())
    name = socket.gethostname()
    with open(config_path, "w") as f:
        json.dump({"peer_id": peer_id, "name": name}, f)
    return peer_id, name


class Discovery:
    """Runs the broadcast announce loop and the listener loop concurrently."""

    def __init__(self, peer_id: str, name: str, tcp_port: int, registry: PeerRegistry):
        self.peer_id = peer_id
        self.name = name
        self.tcp_port = tcp_port
        self.registry = registry
        self._sock: Optional[socket.socket] = None

    def _make_broadcast_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", BROADCAST_PORT))
        sock.setblocking(False)
        return sock

    async def _announce_loop(self) -> None:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        payload = json.dumps({
            "type": "announce",
            "peer_id": self.peer_id,
            "name": self.name,
            "tcp_port": self.tcp_port,
        }).encode("utf-8")

        try:
            while True:
                try:
                    send_sock.sendto(payload, ("255.255.255.255", BROADCAST_PORT))
                except OSError:
                    # e.g. network temporarily unavailable — skip this cycle
                    pass
                await asyncio.sleep(ANNOUNCE_INTERVAL)
        finally:
            send_sock.close()

    async def _listen_loop(self) -> None:
        self._sock = self._make_broadcast_socket()
        loop = asyncio.get_event_loop()

        try:
            while True:
                try:
                    data, addr = await loop.sock_recvfrom(self._sock, 4096)
                except OSError:
                    await asyncio.sleep(0.5)
                    continue

                self._handle_packet(data, addr)
        finally:
            self._sock.close()

    def _handle_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            msg = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        if msg.get("type") != "announce":
            return
        if msg.get("peer_id") == self.peer_id:
            return  # ignore our own broadcast

        ip = addr[0]
        self.registry.upsert(
            peer_id=msg["peer_id"],
            name=msg.get("name", ip),
            ip=ip,
            tcp_port=msg.get("tcp_port", 0),
        )

    async def _prune_loop(self) -> None:
        while True:
            self.registry.prune_stale()
            await asyncio.sleep(PEER_TIMEOUT / 2)

    async def run(self) -> None:
        """Run announce, listen, and prune loops until cancelled."""
        await asyncio.gather(
            self._announce_loop(),
            self._listen_loop(),
            self._prune_loop(),
        )


if __name__ == "__main__":
    # Minimal manual test: run this on two devices on the same LAN/hotspot
    # and watch peers appear/disappear in the console.
    def _on_new(peer: Peer) -> None:
        print(f"[+] Peer online : {peer.name} ({peer.peer_id[:8]}) at {peer.ip}:{peer.tcp_port}")

    def _on_lost(peer: Peer) -> None:
        print(f"[-] Peer offline: {peer.name} ({peer.peer_id[:8]})")

    async def _main() -> None:
        peer_id, name = load_or_create_identity()
        print(f"Starting as {name} ({peer_id[:8]})")
        registry = PeerRegistry(on_peer_new=_on_new, on_peer_lost=_on_lost)
        discovery = Discovery(peer_id, name, tcp_port=5555, registry=registry)
        await discovery.run()

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
