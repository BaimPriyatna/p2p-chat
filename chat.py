"""
chat.py — chat message sending with delivery acknowledgment.

Sits on top of peer.ConnectionManager. Adds:
  - status tracking per outgoing message_id: "sent" -> "delivered" | "failed"
  - automatic chat_ack reply whenever an incoming "chat" message is received
  - a timeout that marks a message "failed" if no ack arrives in time

No retry/resend on failure — by design (see project notes): a peer's IP may
have changed since the message was sent, so blind retry isn't reliable.
The caller decides whether to resend manually.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

import protocol
from peer import ConnectionManager

ACK_TIMEOUT = 5.0  # seconds to wait for chat_ack before marking a message failed

OnChatReceived = Callable[[str, dict], Awaitable[None]]  # (addr_key, message) -> None
OnStatusChange = Callable[[str, str], None]  # (message_id, new_status) -> None


@dataclass
class SentMessageState:
    message_id: str
    addr_key: str
    status: str = "sent"  # sent -> delivered | failed
    sent_at: float = field(default_factory=time.time)
    timeout_task: Optional[asyncio.Task] = None


class ChatSession:
    def __init__(
        self,
        manager: ConnectionManager,
        on_chat_received: Optional[OnChatReceived] = None,
        on_status_change: Optional[OnStatusChange] = None,
    ):
        self.manager = manager
        self.on_chat_received = on_chat_received
        self.on_status_change = on_status_change
        self._pending: dict[str, SentMessageState] = {}

        # Wrap the manager's message dispatch so we intercept chat/chat_ack
        # before/alongside whatever the caller already wired up.
        self._user_on_message = manager.on_message
        manager.on_message = self._dispatch

    async def _dispatch(self, addr_key: str, message: dict) -> None:
        msg_type = message.get("type")

        if msg_type == "chat":
            await self._handle_incoming_chat(addr_key, message)
        elif msg_type == "chat_ack":
            self._handle_ack(message)
        else:
            # not ours — pass through to whatever the caller originally set
            if self._user_on_message:
                await self._user_on_message(addr_key, message)

    async def _handle_incoming_chat(self, addr_key: str, message: dict) -> None:
        # Auto-acknowledge receipt immediately.
        ack = protocol.make_chat_ack(message["message_id"])
        await self.manager.send(addr_key, ack)

        if self.on_chat_received:
            await self.on_chat_received(addr_key, message)

    def _handle_ack(self, message: dict) -> None:
        message_id = message.get("message_id")
        state = self._pending.get(message_id)
        if state is None:
            return  # ack for something we no longer track (e.g. already timed out)

        state.status = "delivered"
        if state.timeout_task:
            state.timeout_task.cancel()
        self._pending.pop(message_id, None)

        if self.on_status_change:
            self.on_status_change(message_id, "delivered")

    async def _timeout_watcher(self, message_id: str) -> None:
        try:
            await asyncio.sleep(ACK_TIMEOUT)
        except asyncio.CancelledError:
            return  # ack arrived in time, nothing to do

        state = self._pending.pop(message_id, None)
        if state is None:
            return  # already resolved
        state.status = "failed"
        if self.on_status_change:
            self.on_status_change(message_id, "failed")

    async def send_chat(self, addr_key: str, sender_id: str, sender_name: str, text: str) -> str:
        """Send a chat message and start tracking it for delivery ack.

        Returns the message_id so the caller can correlate later status
        changes (via on_status_change) back to this send.
        """
        message = protocol.make_chat_message(sender_id, sender_name, text)
        message_id = message["message_id"]

        ok = await self.manager.send(addr_key, message)
        if not ok:
            # Not even connected — report as failed immediately, don't track.
            if self.on_status_change:
                self.on_status_change(message_id, "failed")
            return message_id

        state = SentMessageState(message_id=message_id, addr_key=addr_key)
        state.timeout_task = asyncio.create_task(self._timeout_watcher(message_id))
        self._pending[message_id] = state
        return message_id

    def get_status(self, message_id: str) -> Optional[str]:
        state = self._pending.get(message_id)
        return state.status if state else None


if __name__ == "__main__":
    # Manual interactive test, same usage pattern as peer.py:
    #   python3 chat.py server 5555
    #   python3 chat.py client 5555 <server-ip>
    import sys

    import discovery as _discovery

    async def _main() -> None:
        role = sys.argv[1]
        port = int(sys.argv[2])
        peer_id, name = _discovery.load_or_create_identity()

        async def on_received(addr_key: str, message: dict) -> None:
            print(f"\n<{message['sender_name']}> {message['text']}")

        def on_status(message_id: str, status: str) -> None:
            mark = "\u2713\u2713" if status == "delivered" else "\u2717"
            print(f"  [{mark} {status}] {message_id[:8]}")

        manager = ConnectionManager(listen_port=port, on_message=None)
        chat = ChatSession(manager, on_chat_received=on_received, on_status_change=on_status)
        await manager.start_server()
        print(f"Listening on port {port} as {name} ({peer_id[:8]})")

        addr_key = None
        if role == "client":
            target_ip = sys.argv[3]
            addr_key = await manager.connect_to(target_ip, port)
            print(f"Connected to {addr_key}")

        loop = asyncio.get_event_loop()
        while True:
            text = await loop.run_in_executor(None, input, "")
            keys = list(manager._connections.keys()) or ([addr_key] if addr_key else [])
            if not keys:
                print("(no connection yet)")
                continue
            for k in keys:
                await chat.send_chat(k, peer_id, name, text)

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
