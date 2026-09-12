"""core/security/ — Security architecture and event logging.

Phase 41: Security Event Logging (SECURITY_MODEL.md §29).
"""

from .events import (
    SecurityEvent,
    SecurityEventType,
    SecuritySeverity,
    add_listener,
    capture_security_events,
    emit,
    remove_listener,
)

__all__ = [
    "SecuritySeverity",
    "SecurityEventType",
    "SecurityEvent",
    "emit",
    "add_listener",
    "remove_listener",
    "capture_security_events",
]
