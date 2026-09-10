# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Nothing yet

## [1.3.1] — Phase 3.1–3.3: Ed25519 device identity module

### Added
- **`core/identity/` package** (IMPLEMENTATION_PLAN.md Phase 3) — not yet
  wired into `discovery.py` (that's the next sub-step). Standalone and
  fully tested on its own:
  - `device_identity.py` — `generate_keypair()` / `keypair_from_private_pem()`
    using the `cryptography` library's Ed25519 (no hand-rolled crypto, per
    Phase 3's explicit instruction). `device_id = SHA256(raw public key
    bytes)`, hex-encoded — provably tied to the key that backs it, unlike
    the random UUID it's replacing (see Phase 3.0's rationale).
  - `key_storage.py` — `KeyStore`: private key goes to the OS keyring
    (Secret Service / Credential Manager / Keychain) via the `keyring`
    library when a real backend exists, falling back to a 0600-permission
    plaintext file when it doesn't (e.g. this dev sandbox — verified: no
    keyring backend here, `KeyStore` correctly falls back and the file
    lands at exactly `0600`).
  - `fingerprint.py` — colon-separated hex formatting of a device_id
    (SSH/TLS-style), for the human-comparable fingerprint Phase 4's
    trust-on-first-use flow will need.
  - `identity_file.py` — `load_or_create_identity()`: ties the above
    together. Private key stored via `KeyStore`; public metadata
    (`device_id`, `public_key`, `name`, `created_at`) in a separate plain
    JSON file. Detects and raises `IdentityError` on a corrupted/
    out-of-sync state (identity file present but key missing, or key
    doesn't match the recorded device_id) rather than silently
    regenerating or misbehaving.

### Dependencies
- Added `cryptography` and `keyring` to `pyproject.toml`.

### Compatibility
- Purely additive — no existing module was touched. `discovery.py` still
  uses the old UUID-based `peer_id` for now.

## [1.3.0] — Phase 1.3: binary framing for file transfer

**Note on versioning:** this change breaks file-transfer interop between
peers on `<1.3.0` and `1.3.0+` (chat/handshake are unaffected). Kept as a
MINOR bump rather than MAJOR — a deliberate call while still inside
Phase 1 of active development with no external users yet; revisit this
policy once there's a real install base to consider.

### Changed
- **File chunks now travel as raw binary frames instead of base64-in-JSON**
  (IMPLEMENTATION_PLAN.md Phase 1.3, closes BUG-006/BUG-007). New module
  `core/protocol/binary.py` defines the `file_data` wire layout: a fixed
  28-byte header (16-byte UUID `transfer_id` + 4-byte `sequence` +
  8-byte `offset`) followed by the raw chunk bytes — no JSON, no base64.
  - Overhead per 64 KB chunk: **33.6% → 0.05%** (measured), roughly 25%
    fewer bytes on the wire for a file transfer overall.
  - `core/protocol/frame.py`: the length-prefix header now reserves its
    top bit as an is-binary flag (`BINARY_FLAG`). Real payload lengths
    never legitimately set that bit (max is 100 MB, the flag is bit 31),
    so this is fully backward compatible with the existing
    `[4-byte length][JSON payload]` format — old raw frames decode
    identically. New: `read_any_frame()` (returns `("json", dict)` or
    `("binary", bytes)`), `encode_binary_frame()` / `write_binary_frame()`.
  - `peer.py`: `ConnectionManager._read_loop` now branches on frame kind;
    binary frames are decoded and handed to `on_message` as a synthetic
    `{"type": "file_data", ...}` dict, so no change was needed to the
    `on_message` callback interface itself. New `ConnectionManager.send_binary()`.
  - `file_transfer.py`: `_send_chunks` / `_handle_chunk` rewritten for the
    binary path. `make_file_chunk`/the old `file_chunk` JSON type are no
    longer used by the app (kept in `messages.py` for compatibility) —
    replaced by `sequence`+`offset` validation, which is a strict
    superset of the old chunk-index-only reorder check (BUG-008).
  - The old per-chunk `is_last` flag is gone (no longer meaningful for a
    binary frame without extra header cost); BUG-009's guarantee — a
    transfer can't be declared done with incomplete bytes — is still
    fully enforced in `_handle_done` (`bytes_received == size` AND
    checksum match required before `file_complete_ack(success=True)`).

### Compatibility
- Non-file-transfer messages (chat, hello, etc.) are completely unaffected
  — same JSON frames, same header size, same behavior.
- 3 tests in `test_security_fixes.py` that hand-crafted `file_chunk`
  messages were updated to craft binary `file_data` frames instead
  (same attack scenarios: oversized chunk, out-of-order chunk, bogus
  `file_done` checksum). `test_stage4.py` required zero changes since it
  only exercises the public `offer_file()`/callback API.
- Verified: 12/12 security+upgrade tests, 3/3 stage sanity scripts, plus
  an ad hoc 5 MB / ~80-chunk end-to-end transfer with checksum
  verification — all passing.

## [1.2.0] — Phase 1.2: protocol version field

### Added
- **`version` field on every message** (IMPLEMENTATION_PLAN.md Phase 1.2) —
  `core/protocol/messages.py` gains `PROTOCOL_VERSION = 2`, and every
  `make_*()` factory now stamps its output with `"version": PROTOCOL_VERSION`.
  This is the hook future protocol changes (encryption, identity handshake)
  will use to detect what a peer speaks before sending it something it
  can't parse.
- `validate_message()` now checks `version`: missing entirely is treated as
  legacy version 1 (messages from a peer on a pre-1.2 build, before this
  field existed) rather than rejected, but a non-int value or a version
  below `MIN_SUPPORTED_VERSION` (currently 1) is rejected with
  `ProtocolError`.

### Compatibility
- Wire-format-additive only — no existing field removed or renamed.
  Verified against the full test suite (12 security/upgrade tests + 3 stage
  sanity scripts, all passing) with no test changes required.

## [1.1.1] — Phase 1.1: split protocol layer

### Changed
- **Protocol module restructured** (IMPLEMENTATION_PLAN.md Phase 1.1) —
  `protocol.py` split into `core/protocol/{frame,messages,errors}.py`:
  - `core/protocol/frame.py` — length-prefixed wire framing
    (`encode_frame` / `read_frame` / `write_frame`), independent of message
    semantics.
  - `core/protocol/messages.py` — message type constants, `make_*` factory
    functions, and `validate_message()` schema validation.
  - `core/protocol/errors.py` — `ProtocolError`.
  - Root `protocol.py` kept as a backward-compatible shim re-exporting the
    same public API (`encode_message`/`read_message`/`write_message` alias
    the renamed `encode_frame`/`read_frame`/`write_frame`), so
    `chat.py`, `peer.py`, `file_transfer.py`, `ui.py`, and all existing
    tests required no changes.
- No behavior change. Verified via full test suite: 12/12
  (`test_security_fixes.py`, `test_upgrade_fixes.py`) + 3/3 stage sanity
  scripts (`test_stage2.py`–`test_stage4.py`), all passing.

## [1.0.0] — Initial release

### Added
- **Discovery** (`discovery.py`) — UDP broadcast peer discovery (MNDP-style).
  Stable `peer_id` (UUID) persisted locally so a peer survives IP changes
  from DHCP or switching networks (e.g. LAN to WiFi hotspot). Peer registry
  automatically prunes stale/offline peers after a timeout.
- **Protocol** (`protocol.py`) — length-prefixed JSON wire format (4-byte
  big-endian length header + UTF-8 JSON payload). Message types: `announce`,
  `chat`, `chat_ack`, `file_offer`, `file_accept`, `file_reject`,
  `file_chunk`, `file_done`.
- **Transport** (`peer.py`) — `ConnectionManager`: TCP server for incoming
  connections, `connect_to()` for outgoing connections, per-connection
  async read loop dispatching to a message callback.
- **Chat with delivery acknowledgment** (`chat.py`) — `ChatSession` tracks
  each sent message's status (`sent` → `delivered` / `failed`), auto-replies
  with `chat_ack` on receipt, and marks a message failed either immediately
  (not connected) or after a timeout (default 5s, no ack received). No
  automatic retry — a peer's IP may have changed since the message was sent.
- **Staged file transfer** (`file_transfer.py`) — `FileTransferSession`:
  offer → accept/reject → chunked send (64 KB chunks, base64-in-JSON) →
  checksum-verified completion (SHA-256, checked on both source and
  destination). Rejected offers and checksum mismatches leave no partial
  file on the receiver's disk.
- **Terminal UI** (`ui.py`) — Textual-based `ChatApp` tying everything
  together: live peer list, chat log with delivery status, input box with
  `/msg`, `/send`, `/help` commands, and a modal accept/reject dialog for
  incoming file offers.
- Per-stage automated verification scripts: `test_stage2.py` (chat
  round-trip), `test_stage3.py` (ack/delivery/timeout), `test_stage4.py`
  (chunked transfer + checksum, reject flow), `test_stage5.py` (UI headless
  smoke test) — all passing.
- `README.md` documenting features, architecture, usage, and known
  limitations; `requirements.txt`; `.gitignore`; MIT `LICENSE`.
