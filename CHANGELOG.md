# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Nothing yet

## [1.8.0] — Phase 8 complete: ChaCha20-Poly1305 encrypted channel

### Added
- **`core/crypto/encryption.py`** (Phase 8): `SecureChannel` — a ChaCha20-Poly1305
  AEAD channel built on Phase 7's `SessionKeys` (independent `send_key`/`recv_key`
  per direction).
  - **Sequence-derived nonce, not random**: `nonce = sequence.to_bytes(12, "big")`.
    Uniqueness is guaranteed by construction (a monotonic counter can't repeat
    within a session) rather than relying on random-96-bit collision odds — and
    it means the nonce never needs to travel on the wire, since both sides
    already track their own counter.
  - `encrypt(plaintext, associated_data=b"")` → `EncryptedFrame(sequence, ciphertext)`,
    auto-incrementing sequence.
  - `decrypt(sequence, ciphertext, associated_data=b"")` enforces **strict,
    gap-free sequence order** per direction — a replayed frame, an
    out-of-order frame, or a frame from a different session's keys are all
    rejected (`ReplayOrReorderError` / `DecryptionError`), the same rigor
    already applied to file_data chunks' sequence+offset checks (BUG-008).
  - `SequenceExhaustedError` if a direction's 12-byte counter would overflow
    (a session must be re-handshaked at that point, not reused past it).
- 11 new tests (`tests/test_encryption.py`): round-trip, sequence tracking,
  tampered ciphertext, wrong key, replay, out-of-order, direction
  independence (a channel can't decrypt its own sent traffic), nonce
  determinism, sequence range validation, key-length validation, AAD
  mismatch detection.

### Compatibility
- Purely additive — no existing module touched. Not yet wired into
  `peer.py`'s connection handling (that's Phase 9, Secure Transport Layer).
- Verified: full 44-test pytest suite + 4 stage sanity scripts, all passing.

## [1.7.0] — Phase 7 complete: session key derivation (X25519 + HKDF)

### Added
- **`core/crypto/kdf.py`** (Phase 7):
  - HKDF-SHA256 (RFC 5869) session key derivation: `derive_session_keys(shared_secret, salt, is_initiator)`.
  - Cryptographic domain separation with distinct context tags:
    - `b"peerc-v2:initiator-to-responder"` (32-byte key)
    - `b"peerc-v2:responder-to-initiator"` (32-byte key)
    - `b"peerc-v2:session-id"` (16-byte unique session identifier)
  - Directional keys via `SessionKeys` (`send_key`, `recv_key`, `session_id`):
    - Guaranteed symmetry: initiator's `send_key` matches responder's `recv_key`, and initiator's `recv_key` matches responder's `send_key`.
    - Key separation: `send_key != recv_key` on the same host, preventing reflection and cross-direction key reuse attacks.
  - Transcript hash binding: uses the 32-byte authenticated handshake transcript hash as HKDF salt, ensuring derived session keys are strictly bound to the exact authenticated session.
  - Safe key representation: `SessionKeys.__repr__` masks raw key material (`***`) preventing accidental secret leakage in console logs or tracebacks.
  - Error handling: `KDFError` for invalid types or invalid key/salt lengths.
- **`core/crypto/handshake.py`**:
  - Added convenience method `HandshakeResult.derive_session_keys(is_initiator: bool) -> SessionKeys`.
- **`core/crypto/__init__.py`**:
  - Re-exports `KDFError`, `SessionKeys`, and `derive_session_keys`.
- **`tests/test_kdf.py`**:
  - Automated tests covering determinism, directional symmetry, key separation, transcript binding (avalanche effect), shared secret sensitivity, input validation, masked repr, and end-to-end TCP loopback integration with `perform_handshake_initiator` and `perform_handshake_responder`.
- **`.github/workflows/tests.yml`**:
  - Added `tests/test_kdf.py` to the CI pytest suite.

### Compatibility
- Additive module. No breaking changes. Version bumped to `1.7.0` (MINOR: whole phase complete).

## [1.6.0] — Phase 6 complete: secure authenticated handshake

### Added
- **`core/crypto/key_exchange.py`** (Phase 6.1):
  - Ephemeral X25519 keypair generation (`EphemeralKeypair`, `generate_ephemeral_keypair()`).
  - Raw and hex public key serialization (`ephemeral_public_from_bytes()`, `ephemeral_public_from_hex()`).
  - Diffie-Hellman shared secret computation (`compute_shared_secret()`), providing forward secrecy for sessions.
- **`core/crypto/handshake.py`** (Phase 6.2):
  - 3-way mutual authentication handshake state machine:
    1. `handshake_init`: initiator sends `device_id`, `public_key` (Ed25519), `ephemeral_key` (X25519), `nonce`, and `sender_name`.
    2. `handshake_response`: responder validates identity and trust, generates ephemeral key & nonce, signs the cumulative transcript, and returns signature.
    3. `handshake_finish`: initiator validates responder signature and trust, signs cumulative transcript, and completes handshake.
  - Transcript binding (`compute_responder_transcript`, `compute_initiator_transcript`, `compute_final_transcript_hash`): prevents man-in-the-middle parameter tampering or key substitution attacks.
  - Integration with `core/trust/store.py`: evaluates `TrustStore.check()`, auto-rejects `REVOKED` devices and `KEY_CHANGED` devices, records first-seen peers as `PENDING`, and updates `last_seen`.
  - Replay protection with `NonceCache` tracking fresh 32-byte nonces.
  - Enforced `HANDSHAKE_TIMEOUT = 5.0s`.
  - Asynchronous stream drivers `perform_handshake_initiator()` and `perform_handshake_responder()`.
- **`core/protocol/messages.py`**:
  - Message factories: `make_handshake_init()`, `make_handshake_response()`, `make_handshake_finish()`.
  - Wire schema validation in `REQUIRED_FIELDS` and `validate_message()`.
  - Re-exported via `core.protocol` and root `protocol.py`.
- **`tests/test_handshake.py`**:
  - Full automated coverage: ephemeral key exchange, message schemas, deterministic transcript hashing, loopback TCP handshake integration, and all mandatory security cases from Phase 30 (fake identity rejection, invalid signature rejection, MITM tampering rejection, replay detection, revoked device rejection, key change rejection, and handshake timeout).

### Compatibility
- Additive protocol extension. Re-exports through `protocol.py` preserve existing imports. Version bumped to `1.6.0` (MINOR: whole phase complete).

## [1.5.0] — Phase 4 complete: trust store + TOFU + revocation

### Added
- **`core/trust/revocation.py`** (Phase 4.2) — `revoke_device(store,
  device_id, revoked_by, reason=None)`: marks a device `REVOKED` locally
  and records an audit trail (`revoked_by`, `revoked_at`, `revoke_reason`).
  `is_revoked()` convenience check.
  - **Local-only for this phase, by design**: revocation isn't propagated
    to any other peer yet — there's no authenticated channel to send it
    over until Phase 6's handshake exists. Propagation is explicitly
    deferred, not forgotten.
  - Once `REVOKED`, a device can't silently become `TRUSTED` again —
    both `revoke_device()` (double-revoke) and `TrustStore.approve()`
    (approving a revoked device) refuse and raise rather than allow a
    quiet reversal.

### Compatibility
- Purely additive. Verified: revoke records a correct audit trail,
  double-revoke and revoke-unknown-device are rejected, `approve()`
  correctly refuses a revoked device, and `TrustStore.check()` reports
  `REVOKED` afterward. Existing 15/15 test suite unaffected.

### Note
- Phase 4 (this release) delivers `core/trust/` as a complete, standalone,
  tested primitive — TOFU evaluation, approval, and local revocation all
  work and are covered by tests. It is **not yet wired into any actual
  peer connection** (`peer.py`, `discovery.py`, `ui.py` are untouched):
  there's no cryptographic handshake yet for a `device_id`/`public_key`
  pair to be checked *against*. That wiring happens in Phase 6 (Secure
  Handshake), once a peer connection actually carries a signed identity
  to check trust against.

## [1.4.1] — Phase 4.1: trust store (SQLite) + TOFU logic

### Added
- **`core/trust/` package** (IMPLEMENTATION_PLAN.md Phase 4) — standalone,
  not yet wired into peer.py/discovery.py/ui.py (there's no handshake yet
  to wire it into — that's Phase 6):
  - `device.py` — `TrustedDevice` dataclass, `TrustStatus` enum
    (`PENDING` / `TRUSTED` / `REVOKED`).
  - `store.py` — `TrustStore`, backed by SQLite (stdlib `sqlite3`) at
    `~/.peerc/trust.db`, table `trusted_devices` matching the schema
    in IMPLEMENTATION_PLAN.md. TOFU is deliberately split into a
    **read-only** `check(device_id, public_key)` (returns `UNKNOWN` /
    `PENDING` / `TRUSTED` / `KEY_CHANGED` / `REVOKED`) and separate
    write operations (`record_first_seen`, `approve`) that only run on
    an explicit caller action — `check()` never mutates state, and a
    `public_key` mismatch for a known `device_id` is *never*
    auto-corrected (that would defeat the point of TOFU: it's the signal
    a human needs to see and decide about, not something to paper over).

### Compatibility
- Purely additive. Verified standalone: full TOFU life cycle (unknown →
  first-seen/PENDING → approved/TRUSTED → key-change detection with the
  stored key confirmed unchanged → re-insertion correctly rejected →
  `last_seen` bump → filtered listing by status).

## [1.4.0] — Phase 3 complete: device identity wired in

### Changed
- **`discovery.py`: `peer_id` is now an Ed25519-derived `device_id`**
  (Phase 3.4, closes BUG-003) — `load_or_create_identity()` and
  `save_identity()` now delegate to `core.identity` under the hood, while
  keeping their old call signatures (`(peer_id, name)` tuple in / out) so
  `chat.py`, `ui.py`, and `peer.py` needed zero changes.
  - `save_identity()` now rejects a `peer_id` that doesn't match the
    identity file's recorded `device_id` (`ValueError`) instead of
    silently overwriting — renaming is still supported, reassigning
    someone else's identity is not.
  - **Not migrated**: old pre-Phase-3 identity files
    (`.peerc_identity.json`, bare `{"peer_id": <uuid>, "name": ...}`) are
    left untouched and unused. There's nothing to migrate — a UUID has no
    keypair behind it. Any device upgrading to `1.4.0` gets a new,
    provable `device_id` (and a fresh default identity file at
    `~/.peerc/identity.json`) the first time it runs.

### Compatibility
- **Breaking for existing deployments**: peers on `<1.4.0` and `1.4.0+`
  will show up with different-looking IDs and, since discovery keys peers
  by `peer_id`, effectively look like "new" peers to each other after the
  upgrade. Expected and intentional — this is the whole point of moving
  off unauthenticated UUIDs (see Phase 3.0's rationale). No user-facing
  chat/file-transfer behavior changes; this only affects how peers are
  identified.
- Verified: full 15/15 existing test suite (unchanged, all still green),
  plus new end-to-end coverage of `discovery.py`'s wiring: first-run
  generation, reload consistency, rename, and rejection of a mismatched
  `peer_id` on rename.

### Note
- Phase 3 delivers the identity primitive only — device_id is generated,
  stored, and now used as `peer_id` in discovery. It is **not yet used
  for anything cryptographic**: no signing, no verification, no
  authenticated handshake. That's Phase 4 (Trust Store) and Phase 6
  (Secure Handshake).

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
