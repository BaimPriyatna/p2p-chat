# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Nothing yet

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
