"""
test_stage5.py — headless smoke test for ui.py using Textual's test harness.

Runs the app in memory (no real terminal needed), types a /help command,
and checks it renders without crashing. This isn't a full integration test
of networking + UI together — it verifies the UI itself mounts, wires up
discovery/chat/file_transfer sessions, and responds to input.
"""

import asyncio

from ui import ChatApp


async def main() -> None:
    app = ChatApp()
    async with app.run_test() as pilot:
        await pilot.pause(0.5)  # let on_mount finish (starts discovery, server)

        assert app.peer_id, "peer_id should be set after mount"
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

        print("UI mounted, sessions wired, /help command handled correctly.")

    await app.manager.close_all()
    print("\nSTAGE 5 TEST: PASSED")


if __name__ == "__main__":
    asyncio.run(main())
