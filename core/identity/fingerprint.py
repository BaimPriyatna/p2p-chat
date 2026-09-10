"""core/identity/fingerprint.py — human-readable device_id formatting.

device_id is a 64-char SHA256 hex digest: accurate, but useless for a
person to read aloud or eyeball-compare with a peer over voice/chat/LAN
(this matters later for Phase 4's trust-on-first-use flow, where a human
needs to actually compare two fingerprints to catch a MITM). This formats
it as colon-separated byte pairs, matching the SSH/TLS convention people
already recognize.
"""


def format_fingerprint(device_id_hex: str, groups_shown: int | None = None) -> str:
    """"7f9132ab..." -> "7f:91:32:ab:...".

    groups_shown limits how many colon-separated byte-groups are shown
    (from the start); None (default) shows the full 32-group digest.
    """
    if len(device_id_hex) % 2 != 0:
        raise ValueError("device_id hex string must have even length")
    pairs = [device_id_hex[i : i + 2] for i in range(0, len(device_id_hex), 2)]
    if groups_shown is not None:
        pairs = pairs[:groups_shown]
    return ":".join(pairs)


def short_fingerprint(device_id_hex: str) -> str:
    """8-byte-group prefix (e.g. "7f:91:32:ab:cd:ef:01:23") — enough to
    spot-check at a glance without reading out the full 32-byte digest."""
    return format_fingerprint(device_id_hex, groups_shown=8)
