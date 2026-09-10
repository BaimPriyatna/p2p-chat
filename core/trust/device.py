"""core/trust/device.py — the shape of a trusted-device record.

IMPLEMENTATION_PLAN.md Phase 4's trusted_devices table, as a Python type
rather than raw sqlite3.Row tuples — store.py builds/returns these.
"""

import enum
from dataclasses import dataclass
from typing import Optional


class TrustStatus(str, enum.Enum):
    """str subclass so these compare/serialize as their plain string value
    (matches what's actually stored in the "status" column) without a
    manual .value everywhere."""

    PENDING = "PENDING"   # seen once (TOFU), not yet approved by the user
    TRUSTED = "TRUSTED"   # user approved; same device_id + same public_key is OK
    REVOKED = "REVOKED"   # explicitly distrusted; never silently re-trust this device_id


@dataclass
class TrustedDevice:
    device_id: str
    public_key: str  # base64-encoded raw Ed25519 public key bytes
    name: str
    first_seen: float
    last_seen: float
    status: TrustStatus
    revoked_by: Optional[str] = None
    revoked_at: Optional[float] = None
    revoke_reason: Optional[str] = None
