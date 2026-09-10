"""core/trust/revocation.py — locally distrust a device (Phase 4.2).

Scope of this phase: local-only. Revoking a device marks it REVOKED in
*this* TrustStore and records who did it and why — it does not yet notify
any other peer that the device has been revoked (there's no network
channel this can ride on until Phase 6's authenticated handshake exists;
propagating revocation is a later phase's problem).

Once REVOKED, a device_id can never silently become TRUSTED again —
TrustStore.approve() explicitly refuses to approve a REVOKED device (see
store.py). Un-revoking, if ever needed, should be its own deliberate,
clearly-logged action — not exposed here as a side door.
"""

from typing import Optional

from .device import TrustedDevice, TrustStatus
from .store import TrustStore


class RevocationError(Exception):
    """Raised when a device can't be revoked (unknown, or already revoked)."""


def revoke_device(
    store: TrustStore, device_id: str, revoked_by: str, reason: Optional[str] = None,
) -> TrustedDevice:
    """Mark a device REVOKED locally.

    revoked_by identifies who/what took the action — e.g. the local
    user's display name, or a fixed string like "user" for a UI-driven
    revoke. Kept as a required, explicit argument rather than an implicit
    "me" so the audit trail (who revoked what) is never ambiguous, and so
    this same function can later record an automated revocation (e.g.
    "auto: key mismatch confirmed malicious") without changing its shape.
    """
    device = store.get(device_id)
    if device is None:
        raise RevocationError(f"cannot revoke unknown device_id {device_id!r}")
    if device.status == TrustStatus.REVOKED:
        raise RevocationError(
            f"device_id {device_id!r} is already REVOKED "
            f"(by {device.revoked_by!r}, reason: {device.revoke_reason!r})"
        )
    return store._set_revoked(device_id, revoked_by=revoked_by, reason=reason)


def is_revoked(store: TrustStore, device_id: str) -> bool:
    """Convenience check — True only for a device that exists and is REVOKED."""
    device = store.get(device_id)
    return device is not None and device.status == TrustStatus.REVOKED
