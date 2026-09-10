"""
discovery.py — MNDP-style peer discovery via UDP broadcast.

Each running instance periodically broadcasts a JSON "announce" packet
containing its stable peer_id, display name, and TCP port. Other instances
listen for these broadcasts and maintain a live peer list, evicting peers
that haven't announced within PEER_TIMEOUT seconds (handles DHCP IP changes
and peers going offline).

Phase 3: peer_id is now a device_id derived from an Ed25519 keypair
(core/identity/), not a random UUID — see core/identity/device_identity.py
for why a bare UUID isn't good enough (anyone could claim any UUID; a
device_id is provably tied to the key that backs it). load_or_create_identity()
below keeps its old (peer_id, name) tuple return shape so chat.py/ui.py/
peer.py didn't need to change, but what's inside peer_id changed completely.
"""

import asyncio
import json
import os
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import core.identity as identity

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


def save_identity(peer_id: str, name: str, config_path: str = identity.DEFAULT_IDENTITY_FILE) -> None:
    """Update the display name in the identity file (used by ui.py's /name
    rename command).

    peer_id is accepted for backward compatibility with the pre-Phase-3
    call signature but is no longer something this function can change:
    device_id is derived from the Ed25519 keypair, not freely assignable.
    If the caller's peer_id doesn't match what's on file, that's a sign
    something's out of sync — better to raise than silently ignore it.
    """
    if not os.path.exists(config_path):
        return  # nothing to rename yet — load_or_create_identity() creates it first

    with open(config_path, "r") as f:
        meta = json.load(f)

    if meta.get("device_id") != peer_id:
        raise ValueError(
            f"save_identity called with peer_id={peer_id!r}, but the identity "
            f"file's device_id is {meta.get('device_id')!r} — refusing to "
            "rename what looks like a different identity"
        )

    meta["name"] = name
    with open(config_path, "w") as f:
        json.dump(meta, f, indent=2)


def get_broadcast_targets() -> list[str]:
    """Find all potential IPv4 broadcast and gateway addresses.

    On mobile hotspot tethering (e.g. Android), sending only to 255.255.255.255
    often fails because the mobile kernel routes 255.255.255.255 over cellular
    data rather than the Wi-Fi AP interface. Including subnet broadcast
    (e.g. 10.186.76.255, 192.168.43.255) and the default gateway IP ensures
    packets reach peers across mobile hotspots and complex LANs.
    """
    import struct
    import subprocess

    targets = {"255.255.255.255"}

    # 1. Parse /proc/net/route on Linux/Android for default gateway
    try:
        with open("/proc/net/route", "r") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) >= 3:
                    dest, gw = fields[1], fields[2]
                    if dest == "00000000" and gw != "00000000":
                        gw_ip = socket.inet_ntoa(struct.pack("<L", int(gw, 16)))
                        targets.add(gw_ip)
    except Exception:
        pass

    # 2. Check `ip` command on Linux / Android Termux for subnet broadcasts
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-f", "inet", "addr", "show"],
            text=True, stderr=subprocess.DEVNULL, timeout=1.0
        )
        for line in out.splitlines():
            parts = line.split()
            if "brd" in parts:
                idx = parts.index("brd")
                if idx + 1 < len(parts):
                    targets.add(parts[idx + 1])
    except Exception:
        pass

    # 3. Check default gateway from ip route
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True, stderr=subprocess.DEVNULL, timeout=1.0
        )
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    targets.add(parts[idx + 1])
    except Exception:
        pass

    return sorted(list(targets))


def get_network_info() -> dict:
    """Return local network diagnostics for peer discovery."""
    targets = get_broadcast_targets()
    local_ips = []
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127."):
                local_ips.append(ip)
    except Exception:
        pass
    return {
        "local_ips": local_ips,
        "targets": targets,
    }


def load_or_create_identity(config_path: str = identity.DEFAULT_IDENTITY_FILE) -> tuple[str, str]:
    """Return (peer_id, name).

    peer_id is now an Ed25519-derived device_id (Phase 3) — generated and
    persisted via core.identity on first run, loaded from the same file on
    every run after. Old pre-Phase-3 identity files (a bare
    {"peer_id": <uuid>, "name": ...} at .peerc_identity.json) are not
    migrated: they used a fundamentally different scheme with no keypair
    behind them, so there's nothing to carry forward. A device upgrading
    to this version gets a new device_id the first time it runs.
    """
    dev_identity = identity.load_or_create_identity(
        name=socket.gethostname(), identity_file=config_path,
    )
    return dev_identity.device_id, dev_identity.name


class Discovery:
    """Runs the broadcast announce loop and the listener loop concurrently."""

    def __init__(self, peer_id: str, name: str, tcp_port: int, registry: PeerRegistry):
        self.peer_id = peer_id
        self.name = name
        self.tcp_port = tcp_port
        self.registry = registry
        self._sock: Optional[socket.socket] = None
        self._send_sock: Optional[socket.socket] = None

    def _get_send_socket(self) -> socket.socket:
        if self._send_sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self._send_sock = sock
        return self._send_sock

    def _make_broadcast_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", BROADCAST_PORT))
        sock.setblocking(False)
        return sock

    def _build_payload(self, reply: bool = True) -> bytes:
        return json.dumps({
            "type": "announce",
            "peer_id": self.peer_id,
            "name": self.name,
            "tcp_port": self.tcp_port,
            "reply": reply,
        }).encode("utf-8")

    def probe_peer(self, ip: str, port: int = BROADCAST_PORT) -> None:
        """Send an immediate direct announce packet to a specific IP."""
        payload = self._build_payload(reply=True)
        try:
            send_sock = self._get_send_socket()
            send_sock.sendto(payload, (ip, port))
        except OSError:
            pass

    def broadcast_now(self) -> None:
        """Send an immediate broadcast across all discovered targets."""
        payload = self._build_payload(reply=True)
        send_sock = self._get_send_socket()
        targets = get_broadcast_targets()
        for target in targets:
            try:
                send_sock.sendto(payload, (target, BROADCAST_PORT))
            except OSError:
                pass

    async def _announce_loop(self) -> None:
        try:
            while True:
                targets = get_broadcast_targets()
                payload = self._build_payload(reply=True)
                send_sock = self._get_send_socket()
                for target in targets:
                    try:
                        send_sock.sendto(payload, (target, BROADCAST_PORT))
                    except OSError:
                        pass
                await asyncio.sleep(ANNOUNCE_INTERVAL)
        finally:
            if self._send_sock:
                self._send_sock.close()
                self._send_sock = None

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
            if self._sock:
                self._sock.close()
                self._sock = None

    def _handle_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            msg = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        if not isinstance(msg, dict):
            return
        if msg.get("type") != "announce":
            return

        # BUG-023: fields were pulled out with bare .get()/indexing and
        # trusted as-is — a crafted packet with peer_id=123 or
        # tcp_port=-999 would sail straight into the registry.
        peer_id = msg.get("peer_id")
        if not isinstance(peer_id, str) or not peer_id:
            return
        if peer_id == self.peer_id:
            return  # ignore our own broadcast

        name = msg.get("name", addr[0])
        if not isinstance(name, str) or not name.strip():
            name = addr[0]
        name = name[:64]  # don't let discovery become an amplified nickname-length bug

        tcp_port = msg.get("tcp_port", 0)
        if not isinstance(tcp_port, int) or not (0 < tcp_port < 65536):
            return

        ip = addr[0]
        self.registry.upsert(peer_id=peer_id, name=name, ip=ip, tcp_port=tcp_port)

        # Bi-directional discovery reply:
        # If the incoming announce permits replies, immediately send a unicast announce back.
        # This circumvents AP isolation or broadcast forwarding drops on mobile hotspots.
        if msg.get("reply", True):
            reply_payload = self._build_payload(reply=False)
            try:
                self._get_send_socket().sendto(reply_payload, (ip, BROADCAST_PORT))
            except OSError:
                pass

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