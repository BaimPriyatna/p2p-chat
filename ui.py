"""
ui.py — terminal UI tying discovery, chat, and file_transfer together.

Layout:
    +------------------+------------------------------+
    | Peers (online)   |  Chat log (active peer)       |
    |                  |                                |
    +------------------+------------------------------+
    | > input box (type text, or /send <path>, /help)   |
    +-----------------------------------------------------+

Commands typed into the input box:
    /msg <peer-name-or-id-prefix>   switch active chat target
    /send <filepath>                offer a file to the active peer
    /help                           show available commands
Anything else is sent as a chat message to the currently active peer.

Incoming file offers pop up a modal asking accept/reject.
"""

import asyncio
import os
from typing import Optional

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Input, Label, ListItem, ListView, RichLog

import chat
import discovery
import file_transfer
from peer import ConnectionManager

UI_TCP_PORT = 5656


class FileOfferModal(ModalScreen[bool]):
    """Blocking prompt shown when a peer offers to send us a file."""

    def __init__(self, sender_name: str, filename: str, size: int):
        super().__init__()
        self.sender_name = sender_name
        self.filename = filename
        self.size = size

    def compose(self) -> ComposeResult:
        size_kb = self.size / 1024
        with Vertical(id="offer-dialog"):
            yield Label(f"{self.sender_name} wants to send you a file:")
            yield Label(f"  {self.filename}  ({size_kb:.1f} KB)")
            with Horizontal():
                yield Button("Accept", id="accept", variant="success")
                yield Button("Reject", id="reject", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "accept")


class ChatApp(App):
    CSS = """
    #main { height: 1fr; }
    #peer-list { width: 28; border: solid $accent; }
    #chat-log { border: solid $accent; }
    #offer-dialog {
        align: center middle;
        background: $panel;
        border: thick $accent;
        padding: 1 2;
        width: 60;
        height: auto;
    }
    """
    BINDINGS = [("ctrl+c", "quit", "Quit")]

    def __init__(self):
        super().__init__()
        self.peer_id: str = ""
        self.display_name: str = ""
        self.registry: Optional[discovery.PeerRegistry] = None
        self.manager: Optional[ConnectionManager] = None
        self.chat_session: Optional[chat.ChatSession] = None
        self.file_session: Optional[file_transfer.FileTransferSession] = None
        self.active_peer_id: Optional[str] = None
        # addr_key changes when a peer's IP changes (DHCP), so we resolve
        # peer_id -> current addr_key at send time via self.registry.

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main"):
            yield ListView(id="peer-list")
            yield RichLog(id="chat-log", wrap=True, markup=True)
        yield Input(placeholder="Type a message, or /help for commands", id="input-box")
        yield Footer()

    async def on_mount(self) -> None:
        self.peer_id, self.display_name = discovery.load_or_create_identity()
        self.title = f"p2p-chat — {self.display_name} ({self.peer_id[:8]})"

        self.registry = discovery.PeerRegistry(
            on_peer_new=self._on_peer_new, on_peer_lost=self._on_peer_lost,
        )
        self.manager = ConnectionManager(listen_port=UI_TCP_PORT, on_message=None)
        self.chat_session = chat.ChatSession(
            self.manager, on_chat_received=self._on_chat_received,
            on_status_change=self._on_status_change,
        )
        self.file_session = file_transfer.FileTransferSession(
            self.manager, downloads_dir="downloads",
            on_offer_received=self._on_offer_received,
            on_progress=self._on_transfer_progress,
            on_complete=self._on_transfer_complete,
        )

        await self.manager.start_server()
        self._discovery = discovery.Discovery(
            self.peer_id, self.display_name, UI_TCP_PORT, self.registry,
        )
        asyncio.create_task(self._discovery.run())
        asyncio.create_task(self._prune_ui_loop())

        log = self.query_one("#chat-log", RichLog)
        log.write(f"[bold cyan]Started as {self.display_name} ({self.peer_id[:8]})[/bold cyan]")
        log.write("Waiting for peers... use /help for commands.")

    async def _prune_ui_loop(self) -> None:
        # PeerRegistry.prune_stale() is normally driven by Discovery.run(),
        # but we also refresh the visible list on a steady cadence.
        while True:
            await asyncio.sleep(2.0)
            self._refresh_peer_list()

    def _refresh_peer_list(self) -> None:
        peer_list = self.query_one("#peer-list", ListView)
        peer_list.clear()
        for peer in self.registry.list_peers():
            marker = "* " if peer.peer_id == self.active_peer_id else "  "
            peer_list.append(ListItem(Label(f"{marker}{peer.name} ({peer.peer_id[:8]})"), name=peer.peer_id))

    def _on_peer_new(self, peer: discovery.Peer) -> None:
        self._log(f"[green]+ {peer.name} came online[/green]")
        self._refresh_peer_list()
        if self.active_peer_id is None:
            self.active_peer_id = peer.peer_id

    def _on_peer_lost(self, peer: discovery.Peer) -> None:
        self._log(f"[red]- {peer.name} went offline[/red]")
        self._refresh_peer_list()

    def _log(self, text: str) -> None:
        try:
            self.query_one("#chat-log", RichLog).write(text)
        except Exception:
            pass  # UI not mounted yet

    def _active_addr_key(self) -> Optional[str]:
        if self.active_peer_id is None:
            return None
        peer = self.registry.get(self.active_peer_id)
        if peer is None:
            return None
        return f"{peer.ip}:{peer.tcp_port}"

    async def _ensure_connected(self, addr_key: str) -> None:
        if not self.manager.is_connected(addr_key):
            ip, port_str = addr_key.rsplit(":", 1)
            await self.manager.connect_to(ip, int(port_str))

    # ---- chat callbacks ----

    async def _on_chat_received(self, addr_key: str, message: dict) -> None:
        self._log(f"[bold]<{message['sender_name']}>[/bold] {message['text']}")

    def _on_status_change(self, message_id: str, status: str) -> None:
        mark = "delivered \u2713\u2713" if status == "delivered" else "failed \u2717"
        self._log(f"[dim]  ({mark})[/dim]")

    # ---- file transfer callbacks ----

    async def _on_offer_received(self, transfer_id: str, filename: str, size: int, sender_name: str) -> bool:
        self._log(f"[yellow]File offer from {sender_name}: {filename} ({size/1024:.1f} KB)[/yellow]")
        accepted = await self.push_screen_wait(FileOfferModal(sender_name, filename, size))
        self._log(f"[yellow]  -> {'accepted' if accepted else 'rejected'}[/yellow]")
        return bool(accepted)

    def _on_transfer_progress(self, transfer_id: str, done: int, total: int) -> None:
        pct = (done / total * 100) if total else 0
        self._log(f"[dim]  transfer {transfer_id[:8]}: {pct:.0f}%[/dim]")

    def _on_transfer_complete(self, transfer_id: str, success: bool, filepath: Optional[str]) -> None:
        if success:
            self._log(f"[green]File received: {filepath}[/green]")
        else:
            self._log(f"[red]File transfer {transfer_id[:8]} failed or was rejected[/red]")

    # ---- input handling ----

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.value = ""
        if not text:
            return

        if text.startswith("/"):
            await self._handle_command(text)
            return

        addr_key = self._active_addr_key()
        if addr_key is None:
            self._log("[red]No active peer. Use /msg <name> to select one.[/red]")
            return

        await self._ensure_connected(addr_key)
        await self.chat_session.send_chat(addr_key, self.peer_id, self.display_name, text)
        self._log(f"[bold blue]<you>[/bold blue] {text}")

    async def _handle_command(self, text: str) -> None:
        parts = text.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "/help":
            self._log(
                "[bold]Commands:[/bold] /msg <name-or-id-prefix>  /send <filepath>  /help"
            )
        elif cmd == "/msg":
            match = next(
                (p for p in self.registry.list_peers()
                 if arg.lower() in p.name.lower() or p.peer_id.startswith(arg)),
                None,
            )
            if match:
                self.active_peer_id = match.peer_id
                self._log(f"[cyan]Active peer -> {match.name}[/cyan]")
                self._refresh_peer_list()
            else:
                self._log(f"[red]No peer matching '{arg}'[/red]")
        elif cmd == "/send":
            if not arg or not os.path.isfile(arg):
                self._log(f"[red]File not found: {arg}[/red]")
                return
            addr_key = self._active_addr_key()
            if addr_key is None:
                self._log("[red]No active peer. Use /msg <name> first.[/red]")
                return
            await self._ensure_connected(addr_key)
            transfer_id = await self.file_session.offer_file(addr_key, arg)
            self._log(f"[cyan]Offered {os.path.basename(arg)} ({transfer_id[:8]})[/cyan]")
        else:
            self._log(f"[red]Unknown command: {cmd}[/red]")


if __name__ == "__main__":
    ChatApp().run()
