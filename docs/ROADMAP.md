# Roadmap

Current version: **1.8.0** (see `../CHANGELOG.md` for full detail on every
release). This file is the scannable status view; `IMPLEMENTATION_PLAN.md`
has the full per-phase design detail, and `SECURE_STORAGE_DESIGN.md` has
the detailed design for Phase 39 specifically.

Versioning policy: PATCH per completed sub-step within a phase, MINOR
when a whole phase completes, MAJOR deferred (no external users yet).

## Done

| Version | Phase | What |
|---|---|---|
| `1.1.1` | 1.1 | Split `protocol.py` into `core/protocol/{frame,messages,errors}.py`, backward-compatible shim |
| `1.2.0` | 1.2 | `version` field on every protocol message |
| `1.3.0` | 1.3 | File chunks: base64-in-JSON → binary frames (33.6% → 0.05% overhead) |
| `1.3.1` | 3.1–3.3 | `core/identity/`: Ed25519 keypair, `KeyStore` (keyring + fallback), fingerprint formatting |
| `1.4.0` | 3.4 | `discovery.py`'s `peer_id` wired to the Ed25519-derived `device_id` |
| `1.4.1` | 4.1 | `core/trust/`: SQLite `TrustStore`, TOFU (`check`/`record_first_seen`/`approve`) |
| `1.5.0` | 4.2 | `core/trust/revocation.py`: local device revocation with audit trail |
| `1.6.0` | 6 | `core/crypto/`: ephemeral X25519 key exchange, authenticated 3-way handshake with Ed25519 transcript signatures, TrustStore integration |
| `1.7.0` | 7 | `core/crypto/kdf.py`: HKDF-SHA256 session key derivation with domain separation, directional tx/rx keys, and transcript hash binding |
| `1.8.0` | 8 | `core/crypto/encryption.py`: ChaCha20-Poly1305 AEAD frame encryption, sequence AAD binding, replay/reorder protection, and `SessionCipher` |

**Phase 1 (Protocol V2), Phase 3 (Device Identity), Phase 4 (Trust
Store), Phase 6 (Secure Handshake), Phase 7 (Session Keys), and Phase 8
(ChaCha20-Poly1305 Encryption) are complete.**

## Designed, not yet coded

| Phase | What | Where |
|---|---|---|
| 39 | Secure Storage (at-rest encryption: passphrase/recovery-code envelope encryption, encrypted vault DB, secure/normal file storage, viewer-cache mitigation) | `SECURE_STORAGE_DESIGN.md` — architecture and every implementation-level detail (schema, key formats, nonce handling, DB lifecycle) fully resolved |
| — | File Viewer (In-memory streaming viewer: Text/Code, Media/Image/Audio, Document/PDF/EPUB) | `FILE_VIEWER_DESIGN.md` — architecture, open-source stack (PyMuPDF, Chafa/Kitty, miniaudio/mpv, Rich), zero-disk-cache security pipeline |

Phase 39 absorbs Phase 27 (Storage) — there's no plan to ship an
unencrypted persisted-chat-history release before encryption catches up.

## Next up (recommended order)

Straight from `IMPLEMENTATION_PLAN.md`'s "Urutan implementasi yang
disarankan" — this is the order that makes sense to build in, not the
numeric phase order in the plan doc:

1. **Phase 9 — Secure Transport Layer** ← next


5. Phase 12/13-20 — File Transfer V2 + remaining hardening (path
   traversal/size/chunk fixes are already done — see BUG_REPORT.md; this
   is the rest)
6. Phase 5 — Discovery V2
7. Phase 26/30 — Event architecture, security test cases
8. **Phase 39 — Secure Storage** (design-complete, see above)
9. Phase 36/37 — UI/security UX
10. Phase 28-35 — logging, performance, concurrency, state machines,
    error protocol
11. Phase 38 — Project structure final (**not done now, deliberately** —
    see note below)
12. Security audit, release

## Why Phase 38 (final project structure) isn't done yet

`IMPLEMENTATION_PLAN.md`'s Phase 38 target structure (`app/`,
`core/transport/`, `core/crypto/`, etc.) assumes modules that don't exist
yet — e.g. `core/transport/secure.py` and `core/crypto/handshake.py`
can't be meaningfully created before Phase 6-9 (handshake, session keys,
encryption) actually exist to put in them. Restructuring into that target
shape now would mean creating empty/placeholder directories for
not-yet-designed code, which is more likely to need re-shuffling later
than to help. What's already been done instead: `tests/` was split out
now (matches the final structure, zero risk, all tests still pass from
the new location), and CI (`.github/workflows/tests.yml`) now runs the
full suite on every push. The `core/` modules that already exist
(`protocol/`, `identity/`, `trust/`) already match their Phase 38
destinations exactly — no rework needed there when the rest of Phase 38
eventually happens.

## How this file stays honest

Update this table whenever a version is tagged in `CHANGELOG.md` — same
commit, so this file and the changelog never drift apart the way
`IMPLEMENTATION_PLAN.md`'s "Urutan implementasi" and "Prioritas versi"
sections had (both had stale ✅/⏳ marks from before this file existed;
fixed alongside adding this one).
