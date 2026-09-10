"""core.trust — SQLite trust store + TOFU + local revocation (Phase 4).

    device.py     — TrustedDevice dataclass, TrustStatus enum
    store.py      — TrustStore: TOFU check()/record_first_seen()/approve()
    revocation.py — revoke_device()/is_revoked(): local-only for now
"""

from .device import TrustedDevice, TrustStatus
from .revocation import RevocationError, is_revoked, revoke_device
from .store import DEFAULT_DB_PATH, TrustDecision, TrustStore

__all__ = [
    "TrustedDevice",
    "TrustStatus",
    "RevocationError",
    "is_revoked",
    "revoke_device",
    "DEFAULT_DB_PATH",
    "TrustDecision",
    "TrustStore",
]
