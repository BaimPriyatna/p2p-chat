"""
test_stage5.py — headless smoke test for ui.py using Textual's test harness.

Runs the app in memory (no real terminal needed), types a /help command,
and checks it renders without crashing. This isn't a full integration test
of networking + UI together — it verifies the UI itself mounts, wires up
discovery/chat/file_transfer sessions, and responds to input.
"""

import asyncio
import os
import shutil
import tempfile

import core.identity as identity
import core.identity.key_storage as ks
import discovery
from ui import ChatApp


async def main() -> None:
    tmpdir = tempfile.mkdtemp(prefix="peerc_stage5_")
    tmp_id = os.path.join(tmpdir, "identity.json")
    tmp_key = os.path.join(tmpdir, "key.pem")
    keystore = ks.KeyStore(plaintext_fallback_path=tmp_key)

    saved_load_identity = identity.load_or_create_identity
    saved_disc_load = discovery.load_or_create_identity

    def _isolated_load(name="peer", identity_file=tmp_id, key_store=None):
        return saved_load_identity(name=name, identity_file=tmp_id, key_store=keystore)

    def _isolated_disc_load(config_path=tmp_id):
        dev = _isolated_load(name="TestUser", identity_file=tmp_id)
        return dev.device_id, dev.name

    identity.load_or_create_identity = _isolated_load
    discovery.load_or_create_identity = _isolated_disc_load

    try:
        app = ChatApp()
        async with app.run_test() as pilot:
            await pilot.pause(0.5)  # let on_mount finish (starts discovery, server)

            assert app.peer_id, "peer_id should be set after mount"
            assert app.event_bus is not None, "EventBus should be created"
            assert app.manager is not None, "ConnectionManager should be created"
            assert app.chat_session is not None, "ChatSession should be created"
            assert app.file_session is not None, "FileTransferSession should be created"

            # Type a command and submit it
            await pilot.click("#input-box")
            await pilot.press(*"/help")
            await pilot.press("enter")
            await pilot.pause(0.2)

            log_widget = app.query_one("#chat-log")
            log_text = "\n".join(str(line) for line in log_widget.lines)
            assert "Commands" in log_text or "/msg" in log_text, f"expected help text in log, got: {log_text!r}"

            print("UI mounted, sessions wired, EventBus active, /help command handled correctly.")

        await app.manager.close_all()
        print("\nSTAGE 5 TEST: PASSED")
    finally:
        identity.load_or_create_identity = saved_load_identity
        discovery.load_or_create_identity = saved_disc_load
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
