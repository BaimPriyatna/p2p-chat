# p2p-chat

![Tests](https://github.com/BaimPriyatna/p2p-chat/actions/workflows/tests.yml/badge.svg)

A terminal-based peer-to-peer chat and file transfer application. No central
server — peers discover each other directly over the local network (LAN or
WiFi hotspot) and communicate directly.

## Features

- [x] Peer discovery via UDP broadcast (MNDP-style), stable peer identity
      that survives DHCP IP changes
- [x] Direct chat with delivery acknowledgment (`sent` → `delivered` / `failed`)
- [x] Staged file transfer with offer/accept/reject and checksum verification
- [x] Terminal UI with peer list, chat log, and notifications

## Architecture

- **Discovery** — each instance periodically broadcasts a UDP "announce"
  packet (`peer_id`, `name`, `tcp_port`). Listeners maintain a live peer
  list keyed by `peer_id` (not IP), so a peer's IP can change — e.g. under
  DHCP renewal or switching from LAN to hotspot — without it being treated
  as a new/different peer. Stale peers are pruned after a timeout.
- **Transport** — once discovered, peers connect directly over TCP to
  exchange chat and file messages.
- **Protocol** — length-prefixed JSON messages: `announce`, `chat`,
  `chat_ack`, `file_offer`, `file_accept`, `file_reject`, `file_chunk`,
  `file_done`.
- **No message queue** — if a peer is offline, messages are not queued or
  retried automatically (by design — the peer's IP may have changed by the
  time it comes back online).

## Requirements

- Python 3.10+
- `textual`, `rich`, `cryptography`, `keyring` (see `requirements.txt`)

## Installation

```bash
git clone <repo-url>
cd p2p-chat
pip install -e .
```

This installs the package and creates the `pchat` command in your environment.

## Usage

Run directly via the console command:

```bash
pchat
```

(Or alternately: `python3 ui.py`)

Run this on two or more devices on the same LAN or WiFi hotspot. Peers
appear automatically in the left panel as they are discovered.

### Mouse & Clipboard
- **Select / Block Text**: Click and drag your cursor over text in the chat log to block/select it.
- **Copy**: Press `Ctrl+C` or `Ctrl+Shift+C` to copy the selected text to your system clipboard (supports Wayland `wl-copy`, X11 `xclip`, and terminal OSC 52).
- **Quit Key**: Press `Ctrl+Q` to quit anytime (or `Ctrl+C` when no text is selected).
- **Switch Peer**: Click any peer in the left sidebar to switch conversations.

### Commands

Type into the bottom input box and hit Enter:

| Command | Description |
|---|---|
| `/help` | Show available commands and keyboard shortcuts |
| `/connect <ip>[:port]` | Connect directly to a peer IP (fixes mobile hotspot / AP isolation) |
| `/peers` | List all discovered peers with IP, port, and status |
| `/msg <name\|id>` | Switch the active chat recipient |
| `/send <filepath>` | Offer a file to the active peer |
| `/nick <new-name>` | Change your display nickname and announce to network |
| `/copy [all\|last]` | Copy last chat message or entire log to clipboard |
| `/clear` | Clear the chat log |
| `/info` (or `/me`) | Display local identity, IP, gateway, and listening ports |
| `/quit` (or `/exit`) | Quit `pchat` (or press `Ctrl+Q`) |

Anything else typed is sent as a chat message to the active peer.
Sent messages show delivery status (`delivered ✓✓` or `failed ✗`).

## Known Limitations

- Not yet tested against WiFi hotspots with AP/client isolation enabled —
  broadcast may not reach other clients in that case
- No retry/resend for messages sent while a peer is offline (intentional —
  the peer's IP may have changed by the time it comes back online)
- File chunks travel as binary frames (28-byte header + raw data, ~0.05%
  overhead) rather than base64-in-JSON — see CHANGELOG.md v1.3.0
- No pause/resume for interrupted file transfers — a failed transfer must
  be re-sent from the start
- No end-to-end encryption yet — traffic is plain TCP on the local
  network (planned: IMPLEMENTATION_PLAN.md Phase 6-9)
- Automated test suite: `pytest tests/test_security_fixes.py
  tests/test_upgrade_fixes.py --asyncio-mode=auto`, plus per-stage
  smoke scripts (`tests/test_stage2.py`–`tests/test_stage5.py`, run
  directly with `python3`). Runs automatically in CI on every push — see
  `.github/workflows/tests.yml`.

## Project Structure

```
p2p-chat/
├── core/
│   ├── protocol/        # wire format / message types / framing
│   ├── identity/         # Ed25519 device identity
│   └── trust/             # SQLite trust store, TOFU, revocation
├── discovery.py        # UDP broadcast peer discovery
├── protocol.py          # backward-compatible shim over core.protocol
├── peer.py               # TCP connection management
├── chat.py               # chat + delivery acknowledgment
├── file_transfer.py      # staged file transfer
├── ui.py                 # Textual terminal UI (entry point)
├── tests/               # automated pytest suite + per-stage smoke scripts
├── .github/workflows/   # CI
├── requirements.txt
├── README.md
├── ROADMAP.md
└── CHANGELOG.md
```

See `ROADMAP.md` for current progress against `IMPLEMENTATION_PLAN.md`'s
phases, and `CHANGELOG.md` for a detailed version history.

## License

MIT

## Roadmap

See `CHANGELOG.md` for release history. Possible future work: end-to-end
encryption, pause/resume for file transfers, room/channel support, chat
history persistence.
