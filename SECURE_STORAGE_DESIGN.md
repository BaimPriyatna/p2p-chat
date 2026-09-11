# Secure Storage — Design Document

Status: **planning only — no code written yet.** All design decisions
(§11) are now resolved. This document is the reference for implementation
once Phase 39 starts (see IMPLEMENTATION_PLAN.md).

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
- KDF: **Scrypt** (decided — see §11 for the comparison against
  Argon2id), via `cryptography.hazmat.primitives.kdf.scrypt` — already a
  dependency (Phase 3), no new dependency added. Migrating to Argon2id
  later, if ever wanted, is cheap under this envelope design: re-wrap
  the DEK under a new KEK, no stored data needs to be touched.

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
  no execution risk. **Auto-lock after 5 minutes idle by default**
  (user-configurable — decided by matching `sudo`'s own well-known
  default timestamp timeout, the exact analogy this session model is
  based on), same idea as a sudo timestamp expiring.
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
  - **A separate "critical action" key for Export** (decided — see §11
    for how this was refined). **Not** a second independent wrap on the
    DEK sitting alongside the passphrase's wrap — that would just be a
    second parallel lock on the same door: compromising *either* secret
    is then enough, which adds an attack surface without adding real
    protection. Instead: entry is sequential and both are required to
    combine —
    1. The already-unlocked session's passphrase-derived key material
       (proof the main passphrase was entered correctly this session).
    2. A freshly-entered critical-action secret, entered right after,
       specifically for this action.
    These two are combined (HKDF) into a single authorization value used
    to gate the Export operation. Neither one alone is sufficient:
    having only the critical-action secret without an unlocked
    passphrase session doesn't work, and having only the unlocked
    session without the critical-action secret doesn't work either. UI
    stays simple either way — enter the main passphrase (if not already
    unlocked this session), then enter the extra key, in sequence. The
    extra key's *entry method* can be a typed secret or a device
    biometric (fingerprint/face/PIN) — but biometrics are always
    delegated to the OS's own biometric API (`fprintd` on Linux, Windows
    Hello, Touch/Face ID on macOS), which only returns a yes/no plus
    releases a device-bound secret. This app never handles raw
    biometric data itself — implementing biometric matching ourselves
    would be well outside this project's scope and needlessly risky.
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
- **`trust.db`** (Phase 4) and the storage database — decided, see below.
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

### Database encryption — decided: whole-file via in-memory SQLite

Neither of the two options originally framed (SQLCipher whole-file vs.
plain-`sqlite3` field-level) won outright, so a third option was chosen
instead: **encrypt the entire database file as one blob at rest; when
unlocked, decrypt it into `sqlite3.connect(':memory:')` (or a
tmpfs-backed file) for the session; re-encrypt and flush back to disk on
lock/exit, plus periodic auto-flush.**

This gets whole-file-equivalent protection — no metadata leaks at all,
since the on-disk artifact is always fully ciphertext — using only the
stdlib `sqlite3` module and the already-present `cryptography` dependency
for the encrypt/decrypt step. No SQLCipher, no new native dependency, no
Python-binding-maintenance risk. Trade-off worth tracking during
implementation: a crash between the last flush and the next one risks
losing recent writes — mitigate with a reasonably frequent auto-flush
interval and/or flushing after any write considered important enough not
to lose (e.g. after each new message, not just periodically).

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
    Strip executable permission bits from the decrypted temp file
    regardless of what it had before encryption. **Detection method
    (decided): custom magic-byte/content sniffing, not a third-party
    library and not an extension blocklist alone.** Check the actual
    file header against the small set of executable/script signatures —
    `MZ` (Windows PE), `\x7fELF` (Linux ELF), Mach-O magic numbers
    (macOS), `#!` shebang (scripts) — narrow enough in scope to implement
    directly without adding a dependency like `python-magic`/`libmagic`
    (which would bring the same native-dependency concern as the
    database-encryption question above, for a problem that's actually
    much narrower than general MIME-type detection). Extension is kept
    only as a secondary UX signal (e.g. flag *harder* if the extension
    disagrees with the sniffed content), never the sole basis for the
    decision — a renamed executable must still be caught by content, not
    missed because its extension said `.txt`. **When detection is
    inconclusive, fail closed: block Open, direct the user to Export
    instead.** Export remains available either way, so failing closed
    here doesn't lock anyone out of their own file — it just adds one
    extra explicit step for anything ambiguous.
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

## 11. Decisions

All resolved as of the latest round of discussion (criteria weighed:
LTS/long-term relevance, security, minimal development conflict,
user comfort, stability). Kept here as a record of the reasoning, not as
open questions anymore.

1. **KDF: Scrypt.** Already available via the `cryptography` dependency
   (Phase 3) — wins on minimal-dev-conflict and stability outright, and
   is still a solid memory-hard KDF on security. Argon2id (the more
   commonly recommended default today, per OWASP) was the stronger
   option on pure security/LTS grounds but needs a new native dependency
   (`argon2-cffi`); rejected for now given the envelope design makes a
   later migration cheap (re-wrap the DEK, no stored data touched) if it
   ever matters more than it does today. PBKDF2 (stdlib `hashlib`, even
   fewer dependencies than Scrypt) was considered and rejected — it adds
   no benefit over Scrypt since Scrypt is already dependency-free here,
   while being meaningfully weaker (not memory-hard).
2. **Database encryption: whole-file via in-memory/tmpfs SQLite** (§5),
   not SQLCipher (native dependency, uneven Python-binding maintenance
   history) and not field-level (leaves metadata readable). This option
   wasn't in the original two-way framing — it was added because it
   satisfies security (no metadata leak at all, same as SQLCipher) *and*
   minimal-dev-conflict/stability (stdlib `sqlite3` + already-present
   `cryptography`, no new dependency) simultaneously, rather than forcing
   a trade-off between them.
3. **Phase ordering: absorbed, not sequenced.** Phase 27 (Storage) is
   folded into this phase rather than shipped first as a standalone,
   unencrypted release — chat history should never exist on disk in
   plaintext even temporarily between "Phase 27 ships" and "Phase 39
   catches up." Implementation still proceeds in small, independently
   tested sub-steps (schema first, encryption layer next), matching the
   PATCH-per-substep discipline used in every phase so far — just not
   released as two separate phases with a plaintext-persistence gap
   between them.
4. **Auto-lock timeout: 5 minutes by default, user-configurable.**
   Matches `sudo`'s own well-known default timestamp timeout — the exact
   analogy this whole session model is built on, so it's a deliberately
   recognizable default rather than an arbitrary number.
5. **Per-file vs. global secure/normal default: per-transfer choice**,
   shown on the incoming-file accept dialog (Normal/Secure radio,
   defaulting to Secure).
6. **Executable/script detection: custom magic-byte sniffing** (§6), not
   a third-party library (`python-magic` would add the same
   native-dependency concern as SQLCipher, for a narrower problem than
   general MIME detection actually requires) and not an extension
   blocklist alone (spoofable). Fails closed — Open is blocked, not
   allowed-with-a-warning, when detection is inconclusive; Export stays
   available as the explicit fallback either way.
7. **Critical-action key mechanics: sequential key-combining, not
   parallel wrapping** (§4). Flagged during discussion as a real gap in
   the original framing: two independently-wrapped copies of the DEK
   (main passphrase OR critical-action key, either sufficient alone) is
   an OR-gate — compromising *either* secret is enough, which adds an
   attack surface without adding protection. Resolved instead as an
   AND-gate: the already-unlocked session's key material and a
   freshly-entered critical-action secret are combined (HKDF) into the
   value that actually authorizes Export, so neither secret alone is
   sufficient. UI-wise this is still just "enter a key" — sequentially,
   main passphrase (if not already unlocked) then the extra key —
   optionally satisfiable via an OS-level biometric prompt instead of
   typing, always delegated to the OS's own biometric API rather than
   this app handling raw biometric data itself.
