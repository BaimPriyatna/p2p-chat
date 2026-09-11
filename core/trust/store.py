"""core/trust/store.py — SQLite-backed trusted_devices store (Phase 4).

TOFU (trust-on-first-use) is intentionally split into two steps that never
happen automatically together:

    1. check(device_id, public_key) — read-only. Tells the caller what's
       going on: never seen before, waiting on approval, trusted and
       matching, trusted but the key CHANGED (possible impersonation/MITM
       — never silently accepted), or revoked.
    2. Only on an explicit caller/user action do record_first_seen() or
       approve() actually write anything. A key mismatch is never
       auto-corrected by this module — that would defeat the point of
       TOFU. (Re-approving a changed key, if ever wanted, is a distinct,
       explicit operation for a later phase, not something check() does.)

Not thread-safe across threads (sqlite3 default); fine for this app, which
drives everything from a single asyncio event loop.
"""

import enum
import os
import sqlite3
import time
from typing import Optional

from .device import TrustedDevice, TrustStatus

DEFAULT_DB_PATH = os.path.expanduser("~/.peerc/trust.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trusted_devices (
    device_id     TEXT PRIMARY KEY,
    public_key    TEXT NOT NULL,
    name          TEXT NOT NULL,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    status        TEXT NOT NULL,
    revoked_by    TEXT,
    revoked_at    REAL,
    revoke_reason TEXT
)
"""


class TrustDecision(str, enum.Enum):
    UNKNOWN = "unknown"          # never seen this device_id before
    PENDING = "pending"          # seen, awaiting user approval, key matches what's on file
    TRUSTED = "trusted"          # approved, key matches what's on file — OK
    KEY_CHANGED = "key_changed"  # device_id known, but public_key does NOT match — WARNING
    REVOKED = "revoked"          # explicitly distrusted


class TrustStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # ---- read -------------------------------------------------------

    def get(self, device_id: str) -> Optional[TrustedDevice]:
        row = self._conn.execute(
            "SELECT * FROM trusted_devices WHERE device_id = ?", (device_id,)
        ).fetchone()
        return _row_to_device(row) if row else None

    def check(self, device_id: str, public_key: str) -> TrustDecision:
        """Read-only TOFU evaluation. Never writes anything."""
        device = self.get(device_id)
        if device is None:
            return TrustDecision.UNKNOWN
        if device.public_key != public_key:
            return TrustDecision.KEY_CHANGED
        if device.status == TrustStatus.REVOKED:
            return TrustDecision.REVOKED
        if device.status == TrustStatus.TRUSTED:
            return TrustDecision.TRUSTED
        return TrustDecision.PENDING

    def list_all(self, status: Optional[TrustStatus] = None) -> list[TrustedDevice]:
        if status is None:
            rows = self._conn.execute("SELECT * FROM trusted_devices ORDER BY last_seen DESC").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM trusted_devices WHERE status = ? ORDER BY last_seen DESC",
                (status.value,),
            ).fetchall()
        return [_row_to_device(r) for r in rows]

    # ---- write --------------------------------------------------------

    def record_first_seen(self, device_id: str, public_key: str, name: str) -> TrustedDevice:
        """Insert a brand-new device as PENDING. Caller should only call
        this after check() returned UNKNOWN — calling it for a device_id
        that already exists raises, rather than silently overwriting a
        possibly-different stored public_key."""
        if self.get(device_id) is not None:
            raise ValueError(
                f"device_id {device_id!r} is already known — use check() first; "
                "record_first_seen() must not overwrite an existing entry"
            )
        now = time.time()
        self._conn.execute(
            "INSERT INTO trusted_devices (device_id, public_key, name, first_seen, last_seen, status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (device_id, public_key, name, now, now, TrustStatus.PENDING.value),
        )
        self._conn.commit()
        return self.get(device_id)

    def touch_last_seen(self, device_id: str) -> None:
        """Bump last_seen on a re-encounter with a matching key. No-op if
        the device isn't known (call check() first)."""
        self._conn.execute(
            "UPDATE trusted_devices SET last_seen = ? WHERE device_id = ?",
            (time.time(), device_id),
        )
        self._conn.commit()

    def approve(self, device_id: str) -> TrustedDevice:
        """User has seen the fingerprint and approved it: PENDING -> TRUSTED.

        Refuses to approve a device that's REVOKED (must be un-revoked
        through a deliberate separate action, not this) or that doesn't
        exist yet.
        """
        device = self.get(device_id)
        if device is None:
            raise ValueError(f"cannot approve unknown device_id {device_id!r}")
        if device.status == TrustStatus.REVOKED:
            raise ValueError(
                f"device_id {device_id!r} is REVOKED — approve() refuses to "
                "silently re-trust a revoked device"
            )
        self._conn.execute(
            "UPDATE trusted_devices SET status = ? WHERE device_id = ?",
            (TrustStatus.TRUSTED.value, device_id),
        )
        self._conn.commit()
        return self.get(device_id)

    def _set_revoked(self, device_id: str, revoked_by: str, reason: Optional[str]) -> TrustedDevice:
        """Internal — see core/trust/revocation.py for the public entrypoint."""
        if self.get(device_id) is None:
            raise ValueError(f"cannot revoke unknown device_id {device_id!r}")
        self._conn.execute(
            "UPDATE trusted_devices SET status = ?, revoked_by = ?, revoked_at = ?, revoke_reason = ? "
            "WHERE device_id = ?",
            (TrustStatus.REVOKED.value, revoked_by, time.time(), reason, device_id),
        )
        self._conn.commit()
        return self.get(device_id)


def _row_to_device(row: sqlite3.Row) -> TrustedDevice:
    return TrustedDevice(
        device_id=row["device_id"],
        public_key=row["public_key"],
        name=row["name"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        status=TrustStatus(row["status"]),
        revoked_by=row["revoked_by"],
        revoked_at=row["revoked_at"],
        revoke_reason=row["revoke_reason"],
    )
