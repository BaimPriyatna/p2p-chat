# Secure Storage — Design Document

Status: **planning only — no code written yet.** This document exists to
pin down the design before implementation starts (Phase 39 in
IMPLEMENTATION_PLAN.md). Several open decisions are marked explicitly and
need to be resolved before coding begins.

## 1. What this protects against (threat model)

Two threats were named explicitly and are both in scope:

| # | Scenario | In scope? | Notes |
|---|----------|-----------|-------|
| 1 | Device stolen/lost while **powered off / locked** | Yes | The main case this design is built for — data at rest is ciphertext without the key. |
| 2 | Someone else picks up an **unlocked/running** device | Yes | Session/"sudo" model below: unlocking isn't permanent, and sensitive actions re-prompt. |
| 3 | Malware already running *while the app is unlocked* | **Not fully mitigated** | The decryption key has to live in memory while the app can display messages — any design that can decrypt data for the user can be asked to decrypt it by malware running as that same user. This is a hard limit of client-side at-rest encryption, not something this design pretends to solve. Worth being explicit about this rather than overselling the protection. |
| 4 | Viewer app caching decrypted content outside our control | Yes | Section 6. |
| 5 | Forgetting the passphrase | Yes | Recovery code (section 3). |

**Framing note:** the person described this as working "like ransomware" —
meaning *encrypted-until-unlocked-with-a-key*, which is an accurate
mechanical description. To be clear about what's actually being built:
this is the person encrypting **their own data, with a key only they
control**, the same mechanism behind things like BitLocker, FileVault, or
a password manager's vault — not anything that encrypts a victim's data
against their will or demands payment. Naming it here just to make sure
the design intent is unambiguous in this document.

## 2. Key architecture: envelope encryption

A single passphrase should be able to unlock everything, and it should be
possible to change that passphrase later without re-encrypting every
stored file and every database row. That means the passphrase should not
*be* the encryption key directly — it should only be able to *unwrap* the
real key. Standard envelope-encryption pattern (same idea LUKS/BitLocker
use):

```
                    random, generated once, never leaves this device
                              │
                              ▼
                    ┌──────────────────┐
                    │   DEK (AES-256)   │   ← actually encrypts data
                    └──────────────────┘
                       │              │
             wrapped by │              │ wrapped by
                       ▼              ▼
              KEK(passphrase)   KEK(recovery code)
                       │              │
              derived from      derived from
                       │              │
                 user passphrase   recovery code
              (Scrypt, random salt) (Scrypt, random salt)
```

- **DEK** (Data Encryption Key): one random 256-bit key, generated once
  on first setup. This is what actually encrypts files and database
  content.
- **KEK** (Key Encryption Key): derived from a low-entropy secret
  (passphrase, or the recovery code) via a memory-hard KDF, used only to
  wrap/unwrap the DEK — never to encrypt data directly.
- Both wrapped copies of the DEK are stored together in a small
  `vault_keyfile.json` (not secret by itself — same idea as a LUKS
  header): KDF salts + parameters, both wrapped DEKs, and a fast
  passphrase-verifier hash (so a wrong passphrase fails immediately
  instead of "unwrap succeeds into garbage").
- **Where that keyfile physically lives is a separate question from
  whether a passphrase is required.** It can sit in OS keyring storage
  (same `KeyStore` used for the device's Ed25519 private key — Phase 3)
  purely as a storage location — that does **not** mean the app
  auto-unlocks whenever the OS session is unlocked. Unwrapping the DEK
  always requires the passphrase-derived KEK; keyring here is just
  "where the encrypted blob is kept," not "an alternate unlock path."
  This was an explicit decision after comparing two options: OS-keyring
  auto-unlock (simpler, but doesn't cover "someone else picks up an
  already-unlocked device") vs. mandatory passphrase (the "sudo-style"
  model, chosen) — **mandatory passphrase always required to unlock,
  regardless of where the wrapped-DEK bytes are physically stored.**
- Changing the passphrase later = re-wrap the DEK under a new KEK.
  Nothing already encrypted needs to be touched.
- KDF: **Scrypt**, via `cryptography.hazmat.primitives.kdf.scrypt` — this
  library is already a dependency (Phase 3), so this adds no new
  dependency. (Open decision — see §11: Argon2id is the more commonly
  recommended default today; using it would mean adding `argon2-cffi`.)

## 3. Recovery code

Generated once, at first identity setup (same moment as Phase 3's
`load_or_create_identity()` first run), shown to the user exactly once
on screen with an explicit "write this down, we cannot show it again"
prompt, and never stored by the app in any recoverable form — only a
Scrypt-derived KEK from it is used, once, to wrap a second copy of the
DEK (§2). Losing both the passphrase and the recovery code means the
data is unrecoverable by design; that's the same trade-off every
client-side-encrypted system makes.

## 4. Session model — text chat vs. file actions

Refined after discussion: text chat and file actions have genuinely
different risk profiles and should not share one friction level.

- **Text chat: session-based, WhatsApp-like.** Once the app is unlocked
  (passphrase entered, DEK in memory), reading and sending text messages
  needs no further prompts. Text never leaves the app's own
  in-memory-rendered UI — there's no external viewer, no exported copy,
  no execution risk. Auto-lock after N minutes idle (configurable) still
  applies at the app level, same idea as a sudo timestamp expiring.
- **File actions: key required every time, by default.** Open, Export,
  Move to Secure Storage, and Delete do **not** reuse the app's unlock
  state — each one re-prompts for the passphrase independently,
  regardless of whether the app session is already unlocked for chat.
  This is a deliberate, stricter rule than a single shared session: a
  file action can expose plaintext outside the app's controlled UI (an
  external viewer, a permanent exported copy) in a way reading chat text
  never does, so it doesn't inherit chat's lighter friction.
  - **Incoming Transfer (receiving a file from a peer) is the one
    exception** — a yes/no accept/reject is enough by default. This is a
    different action from Move to Secure Storage: nothing is being
    decrypted or exposed here, the file doesn't exist locally yet at
    all, so there's nothing for a passphrase to protect at this step.
    The passphrase can still be required for incoming transfers too, if
    the user turns that on (see below).
- **User-configurable security level** — the "always ask" default for
  file actions is a default, not a hard floor forced on everyone.
  Exposed as a setting so the friction/convenience trade-off is the
  user's choice, not this design's:
  - **"Don't ask again this session"** — a per-session toggle that skips
    re-prompting for file actions once enabled, falling back to the
    ordinary app-level unlock state (closer to how chat already works).
  - **A separate "critical action" key** — an optional *second*,
    distinct secret specifically for the highest-risk actions (Export
    is the clear candidate: it's the one action that permanently removes
    a file from protection). Lets someone run day-to-day Opens off their
    main passphrase/session while still gating Export behind something
    extra.
  - Whatever the user configures, this is about **convenience vs.
    friction, not about weakening what's encrypted** — the DEK is still
    only ever unwrapped via a passphrase-derived KEK (§2); "don't ask
    again this session" means not re-prompting, not skipping the
    unwrap-with-key step entirely.

## 4a. Text chat and file chat are separate UI areas

Unlike a chat app that inlines file attachments into the text message
timeline, text messages and files get **distinct views**, for both
received and sent files — not interleaved. This follows directly from
§4: since files carry a completely different authentication requirement
(key every time) than text (session-based), mixing them into one
timeline would mean the UI constantly interrupting a chat conversation
with file-specific prompts, or — worse — under-authenticating a file
because it's visually just another chat bubble. A dedicated file area
makes "this needs a key, that doesn't" an obvious property of *where*
something is, not something the user has to track per-item.

## 5. What gets encrypted

- **Chat history & transfer records** — these don't persist anywhere
  yet. Phase 27 ("Storage") is the prerequisite that creates
  `messages`/`transfers`/`devices`/`settings` tables in the first place;
  this phase can't encrypt data that Phase 27 hasn't defined yet. **This
  phase depends on Phase 27 landing first** (or at minimum, its schema
  being finalized).
- **Files in "secure" mode** — stored as an encrypted blob
  (AES-256-GCM), key derived per-file via HKDF from the DEK plus a random
  per-file salt, alongside the ciphertext. "Normal" mode files behave
  exactly as file transfer works today (plaintext on disk).
- **`trust.db`** (Phase 4) — open decision, see §11.
- **Important clarification on "device identity" in the encrypted
  database**: only the *public* metadata (`device_id`, `public_key`,
  `name`, `created_at` — same shape as `identity_file.py`'s current
  plain-JSON metadata) belongs in any database, encrypted or not. The
  **private key never goes in a database, encrypted or otherwise** — it
  stays exclusively in `KeyStore` (Phase 3), matching the existing rule
  from Phase 27's own plan ("Jangan menyimpan private key di SQLite").
  This needed spelling out explicitly because a diagram that lumps
  "device identity" into "encrypted database" reads ambiguously on this
  point otherwise.

### Whole-database vs. field-level encryption — open decision (§11)

Two real options, with different dependency and query-performance
trade-offs:

- **A. Whole-file encryption** (e.g. SQLCipher): the entire SQLite file
  is ciphertext. Strongest protection (no metadata leaks at all), but
  needs a new native dependency (`pysqlcipher3` or similar) — a bigger
  ask than anything added so far (`cryptography`/`keyring` are pure
  Python + stdlib-adjacent).
- **B. Field-level encryption**: keep plain `sqlite3` (stdlib, already in
  use), encrypt only sensitive column values (message text, filenames,
  attachment paths) with the DEK before writing. Metadata needed for
  queries/sorting (timestamps, device_id, message_id, status) stays
  plaintext. Weaker (an attacker with the file learns who-talked-to-whom-
  when, just not content) but zero new dependencies and keeps everything
  else about the storage layer unchanged.

## 6. File lifecycle, naming, and actions

Five distinct, clearly separate actions on a file — worth naming
precisely since they have very different security implications and,
correspondingly, different authentication requirements. Per §4,
Open/Export/Delete/Move-to-Secure re-prompt for the passphrase by
default (user-configurable); Incoming Transfer only needs a yes/no
confirmation — it's the one action here that isn't about an existing
secure file at all.

- **Incoming Transfer** — receiving a file from another peer (the
  accept/reject dialog, with the Normal/Secure choice already covered in
  §5/§11). Yes/no confirmation only, **no passphrase** — nothing is
  being decrypted or exposed yet at this point; accepting just starts
  the transfer and, if Secure was chosen, writes it straight into secure
  storage as it arrives. Not the same action as "Move to Secure
  Storage" below, even though both end with a file in secure storage —
  this one is about a file that doesn't exist locally yet at all.
- **Open** — decrypt to an ephemeral temp location, hand to the default
  external app, and best-effort clean up after. File **stays** in secure
  storage; nothing permanent leaves it. See §10 for why the cleanup is
  still not a full guarantee.
  - **Must never execute the file.** "Open" means view/preview only —
    it must never result in the decrypted content running as a program.
    Concretely: strip executable permission bits from the decrypted temp
    file regardless of what it had before encryption; refuse to hand a
    file with an executable/script extension (`.exe`, `.sh`, `.py`,
    `.bat`, `.app`, etc. — needs a real list, not just these examples)
    to the OS's default-handler mechanism at all, showing a clear "this
    file type can't be opened, only exported" message instead of
    guessing whether the OS would run it. Applies even if the original
    file's *true* type doesn't match its extension — extension-sniffing
    alone isn't a safe way to decide "is this executable," so this needs
    a real design pass (magic-byte/content sniffing, not just filename)
    before implementation, not something to hand-wave in this doc.
- **Export** — decrypt and write a **permanent plaintext copy** outside
  secure storage, at a location the user picks. This is the one that
  actually removes protection from the data (see §8: export flow). Shown
  as a distinct, separately-confirmed action from Open — never implied
  by it. The natural candidate for the optional "critical action" second
  key (§4), since it's the one irreversible-in-effect action here.
- **Move to Secure Storage** — a different action from Incoming Transfer:
  take an existing **local** plaintext file (e.g. something already in
  normal/`Downloads/P2P-Chat/`, or anything else already on disk) and
  encrypt it into secure storage. Requires the passphrase by default,
  same as Open/Export/Delete — it's still a file-storage action touching
  the DEK, unlike Incoming Transfer which doesn't decrypt/expose
  anything.
- **Delete** — remove a secure file (and its ciphertext) entirely.

### Naming/path scheme

Secure and normal storage should look structurally different on disk, not
just be "the same folder but encrypted":

```
~/.local/share/p2p-chat/secure/          ~/Downloads/P2P-Chat/
├── 8f3a1c...◦.p2pfile                   ├── foto.jpg
├── 72bc09...◦.p2pfile                   ├── video.mp4
└── ...                                  └── dokumen.pdf
```

Secure files are named by an opaque id (hash or random), not the
original filename — the original name is metadata, encrypted alongside
the content rather than left readable from a directory listing. Normal
files keep human-readable names, matching today's file-transfer
behavior exactly.

## 7. Settings UI shape

Two related but distinct settings sections (for whichever UI phase this
eventually lands in — Phase 26/36/37):

```
Settings
│
├── Storage
│   ├── Normal Storage  → path picker (default: ~/Downloads/P2P-Chat/)
│   └── Secure Storage  → path picker (default: ~/.local/share/p2p-chat/secure/)
│
└── Security
    ├── Device Identity      (view fingerprint, Phase 3)
    ├── Trusted Devices       (Phase 4's TrustStore, list/revoke)
    ├── Recovery / Backup     (view backup status, regenerate recovery code — step-up re-auth required, §4)
    └── Authentication         (§4's user-configurable friction level)
        ├── Auto-lock timeout (idle minutes before the app re-locks)
        ├── "Don't ask again this session" for file actions — on/off
        └── Critical-action key — set/change a separate key for Export
             (optional; unset by default, main passphrase covers everything)
```

## 8. Export / decrypt flow

Explicit user action only — never automatic. Requires step-up re-auth
(§4). The confirmation step should require an active acknowledgment, not
just a dismissible warning — e.g. a checkbox ("I understand this will be
a plaintext copy outside Secure Storage, readable by anything with
access to that location") that must be checked before the "Export"
button is enabled, not just a warning label next to a button that works
regardless. Produces a plaintext copy in "normal" storage at a location
the user picks. The UI should make clear that the exported copy is no
longer protected by any of this.

## 9. Backup model

Identity and data are backed up as separate concerns, since they have
different sensitivity and different recovery semantics:

```
Backup
  │
  ├── Identity (Ed25519 private key) — via KeyStore's own export path,
  │   never bundled into the same archive as bulk data
  │
  └── Data — message history, trust store, secure files — all still
      encrypted in the backup archive itself (a backup of encrypted data
      should not itself be plaintext)
```

## 10. Viewer cache problem

Correctly flagged as a real gap: handing a decrypted file to an OS-level
default viewer/app means that app's own temp files, thumbnail cache, or
recent-files list can retain the plaintext indefinitely, outside this
app's control entirely.

Mitigation, in order of preference:

1. **Render in-app wherever feasible** — text and common image formats
   shown directly from decrypted bytes in memory, never touching disk at
   all. No external process ever sees the plaintext.
2. **When an external viewer is unavoidable** (a format we can't render
   in-app): decrypt to a memory-backed location if the OS provides one
   (e.g. `/dev/shm` on Linux) with restrictive permissions, and
   best-effort delete-on-close/on-exit.
3. **Be honest about the limit**: "best-effort delete" is not a
   guarantee — the OS can still swap that memory to disk, and the
   external viewer can still cache it internally regardless of where we
   put the source file. The UI should say this plainly rather than imply
   a guarantee this design can't make. (This matches an external review
   of this same design, which independently flagged the identical
   concern — worth taking as confirmation this is a real, not
   theoretical, gap.)

## 11. Open decisions (need a decision before coding starts)

1. **KDF**: Scrypt (no new dependency, already available via
   `cryptography`) vs. Argon2id (more commonly recommended today, needs
   `argon2-cffi`).
2. **Database encryption**: whole-file (SQLCipher, new native dependency)
   vs. field-level (stdlib `sqlite3`, weaker but zero new dependencies).
3. **Phase ordering**: does Phase 27 (Storage) need to be fully built
   first, or can this phase define the encrypted schema directly and
   effectively absorb Phase 27's scope?
4. **Auto-lock timeout**: default idle duration before re-locking, and
   whether it's user-configurable. — *partially resolved*: confirmed
   user-configurable (§4); default duration itself still open.
5. ~~Per-file vs. global secure/normal default~~ — **resolved**:
   per-transfer choice, shown on the incoming-file accept dialog
   (Normal/Secure radio, defaulting to Secure — consistent with "chat is
   always secure," files default to the safer option with an easy
   opt-out per transfer rather than the other way around).
6. **Executable/script detection for the "Open never executes" rule**
   (§6): needs a real content-sniffing approach (magic bytes / MIME
   detection), not just a file-extension blocklist — an extension alone
   is trivially wrong (renamed executable) or trivially annoying (a
   `.py` file that's actually just text someone's sharing). What
   library/approach, and what happens when detection is inconclusive
   (block by default, or warn-and-allow)?
7. **Critical-action key mechanics**: does the optional second key for
   Export (§4) get its own independent envelope-encryption setup (its
   own KEK wrapping a *different* purpose-specific key), or does it
   simply gate the UI step (still unwraps the same DEK, just requires a
   second correct secret before the Export button does anything)? The
   latter is simpler; the former is more genuinely "two keys with
   independent compromise value" but adds real complexity for a feature
   that's opt-in and off by default.
