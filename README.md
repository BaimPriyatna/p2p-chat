# p2p-chat

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
- `textual`, `rich` (see `requirements.txt`)

## Installation

```bash
git clone <repo-url>
cd p2p-chat
pip install -r requirements.txt
```

## Usage

```bash
python3 ui.py
```

Run this on two or more devices on the same LAN or WiFi hotspot. Peers
appear automatically in the left panel as they're discovered.

**Commands** (type into the input box at the bottom):
- `/msg <name-or-id-prefix>` — switch the active chat target
- `/send <filepath>` — offer a file to the active peer (they get an
  accept/reject prompt)
- `/help` — list commands

Anything else typed and submitted is sent as a chat message to the active
peer. Sent messages show a delivery status (`delivered` or `failed`) once
the peer's acknowledgment comes back or times out.

## Known Limitations

- Not yet tested against WiFi hotspots with AP/client isolation enabled —
  broadcast may not reach other clients in that case
- No retry/resend for messages sent while a peer is offline (intentional —
  the peer's IP may have changed by the time it comes back online)
- File chunks are base64-encoded inside JSON frames (~33% size overhead) —
  fine for typical file sharing, not optimized for very large files
- No pause/resume for interrupted file transfers — a failed transfer must
  be re-sent from the start
- No end-to-end encryption — traffic is plain TCP on the local network
- No automated test suite beyond the per-stage manual scripts
  (`test_stage2.py`–`test_stage5.py`)

## Project Structure

```
p2p-chat/
├── discovery.py       # UDP broadcast peer discovery
├── protocol.py        # wire format / message types
├── peer.py             # TCP connection management
├── chat.py             # chat + delivery acknowledgment
├── file_transfer.py    # staged file transfer
├── ui.py               # Textual terminal UI (entry point)
├── test_stage*.py      # per-stage verification scripts
├── requirements.txt
├── README.md
└── CHANGELOG.md
```

## License

MIT

## Roadmap

See `CHANGELOG.md` for release history. Possible future work: end-to-end
encryption, pause/resume for file transfers, room/channel support, chat
history persistence.
