"""tests/test_discovery.py — Phase 5.1: Discovery V2 protocol field tests.

Covers:
  1. Outgoing payload carries version/device_id/public_key (wire spec in
     IMPLEMENTATION_PLAN.md "Phase 5 — Discovery V2").
  2. A well-formed, self-consistent packet is accepted into the registry.
  3. device_id/public_key self-consistency mismatch is dropped and emits
     an AUTH_FAILED SecurityEvent (Phase 41 infra), not registered as a peer.
  4. Malformed public_key (not base64, wrong length) is dropped.
  5. Missing/wrong version is dropped silently (no SecurityEvent — protocol
     mismatch, not an attack).
  6. Own broadcast is still ignored.
  7. Pre-existing BUG-023 field validation (name/tcp_port) still holds.

Deliberately NOT tested here: whether an accepted peer is "trusted" —
that's core/trust/'s job (Phase 4), out of scope for discovery.
"""

import base64
import hashlib
import json

import pytest

from core.identity.device_identity import generate_keypair
from core.security import SecurityEventType, capture_security_events
from discovery import PROTOCOL_VERSION, Discovery, PeerRegistry


def _make_discovery(registry: PeerRegistry | None = None) -> tuple[Discovery, "generate_keypair"]:
    keypair = generate_keypair()
    registry = registry or PeerRegistry()
    disc = Discovery(
        peer_id=keypair.device_id,
        name="tester",
        tcp_port=5656,
        registry=registry,
        public_key=keypair.public_key_bytes(),
    )
    return disc, keypair


def _valid_packet(device_id: str, public_key: bytes, **overrides) -> bytes:
    msg = {
        "type": "announce",
        "version": PROTOCOL_VERSION,
        "device_id": device_id,
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "name": "peer-a",
        "tcp_port": 6000,
        "reply": False,
    }
    msg.update(overrides)
    return json.dumps(msg).encode("utf-8")


def test_build_payload_has_v2_fields():
    disc, keypair = _make_discovery()
    payload = json.loads(disc._build_payload(reply=False))

    assert payload["version"] == PROTOCOL_VERSION
    assert payload["device_id"] == keypair.device_id
    assert base64.b64decode(payload["public_key"]) == keypair.public_key_bytes()
    assert payload["tcp_port"] == 5656


def test_valid_self_consistent_packet_is_registered():
    registry = PeerRegistry()
    disc, _ = _make_discovery(registry)
    peer_keypair = generate_keypair()

    packet = _valid_packet(peer_keypair.device_id, peer_keypair.public_key_bytes())
    disc._handle_packet(packet, ("10.0.0.5", 9999))

    peer = registry.get(peer_keypair.device_id)
    assert peer is not None
    assert peer.name == "peer-a"
    assert peer.tcp_port == 6000
    assert peer.public_key == peer_keypair.public_key_bytes()


def test_device_id_pubkey_mismatch_dropped_and_logged():
    registry = PeerRegistry()
    disc, _ = _make_discovery(registry)
    real_keypair = generate_keypair()
    other_keypair = generate_keypair()

    # Claims real_keypair's device_id but ships other_keypair's public_key.
    packet = _valid_packet(real_keypair.device_id, other_keypair.public_key_bytes())

    with capture_security_events() as events:
        disc._handle_packet(packet, ("10.0.0.6", 9999))

    assert registry.get(real_keypair.device_id) is None
    assert len(events) == 1
    assert events[0].event_type == SecurityEventType.AUTH_FAILED.value
    assert events[0].details["reason"] == "device_id_pubkey_mismatch"
    assert events[0].details["source_ip"] == "10.0.0.6"


@pytest.mark.parametrize("bad_public_key", [
    "not-valid-base64!!!",
    base64.b64encode(b"too-short").decode("ascii"),
    base64.b64encode(b"x" * 33).decode("ascii"),  # wrong length (not 32)
])
def test_malformed_public_key_dropped(bad_public_key):
    registry = PeerRegistry()
    disc, _ = _make_discovery(registry)
    peer_keypair = generate_keypair()

    msg = {
        "type": "announce",
        "version": PROTOCOL_VERSION,
        "device_id": peer_keypair.device_id,
        "public_key": bad_public_key,
        "name": "peer-a",
        "tcp_port": 6000,
        "reply": False,
    }
    packet = json.dumps(msg).encode("utf-8")
    with capture_security_events() as events:
        disc._handle_packet(packet, ("10.0.0.7", 9999))

    assert registry.get(peer_keypair.device_id) is None
    assert events == []  # malformed field, not a self-consistency failure


def test_missing_or_wrong_version_dropped_silently():
    registry = PeerRegistry()
    disc, _ = _make_discovery(registry)
    peer_keypair = generate_keypair()

    for overrides in ({"version": 1}, {}):
        packet = _valid_packet(peer_keypair.device_id, peer_keypair.public_key_bytes())
        msg = json.loads(packet)
        msg.pop("version", None)
        msg.update(overrides)
        packet = json.dumps(msg).encode("utf-8")

        with capture_security_events() as events:
            disc._handle_packet(packet, ("10.0.0.8", 9999))

        assert registry.get(peer_keypair.device_id) is None
        assert events == []


def test_own_broadcast_ignored():
    registry = PeerRegistry()
    disc, keypair = _make_discovery(registry)

    packet = _valid_packet(keypair.device_id, keypair.public_key_bytes())
    disc._handle_packet(packet, ("10.0.0.9", 9999))

    assert registry.get(keypair.device_id) is None


def test_bug_023_field_validation_still_holds():
    """Regression: name/tcp_port validation from BUG-023 must survive the
    Phase 5.1 changes (self-consistency check runs before these, but
    shouldn't short-circuit them for otherwise-valid packets)."""
    registry = PeerRegistry()
    disc, _ = _make_discovery(registry)
    peer_keypair = generate_keypair()

    bad_port_packet = _valid_packet(
        peer_keypair.device_id, peer_keypair.public_key_bytes(), tcp_port=-999,
    )
    disc._handle_packet(bad_port_packet, ("10.0.0.10", 9999))
    assert registry.get(peer_keypair.device_id) is None
