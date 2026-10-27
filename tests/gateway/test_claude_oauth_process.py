"""Owned login groups remain cleanable after the CLI exits, without stale PID signals."""
import asyncio
import os
import sys
from types import SimpleNamespace

import pytest

from gateway.claude_oauth_process import ClaudeLoginProcess


@pytest.mark.platforms("linux")
@pytest.mark.asyncio
@pytest.mark.parametrize("exit_first", [True, False])
async def test_close_kills_remaining_group_after_cli_exit(tmp_path, monkeypatch, exit_first):
    from hermes_platform import resolver

    connected = asyncio.get_running_loop().create_future()
    server = await asyncio.start_server(
        lambda reader, writer: connected.set_result((reader, writer)), "127.0.0.1", 0,
    )
    port = server.sockets[0].getsockname()[1]
    script = tmp_path / "claude.py"
    script.write_text('''import os, signal, socket, sys
child = os.fork()
if child == 0:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1]))) as connection:
        connection.recv(1)
    os._exit(0)
if sys.argv[2] == "exit":
    sys.exit(17)
while True:
    signal.pause()
''', encoding="utf-8")
    monkeypatch.setattr(resolver, "locate_command", lambda name: SimpleNamespace(
        command=(sys.executable, str(script), str(port), "exit" if exit_first else "stay")))
    login = await ClaudeLoginProcess.start(dict(os.environ))
    writer = None
    closed = False
    try:
        reader, writer = await asyncio.wait_for(connected, 10)
        if exit_first:
            assert await asyncio.wait_for(login.wait(), 10) == 17
            assert not login.alive
        else:
            assert login.alive
        assert not reader.at_eof()
        await asyncio.wait_for(login.close(), 10)
        closed = True
        # Only the descendant holds the socket; EOF proves cleanup killed it.
        assert await asyncio.wait_for(reader.read(1), 10) == b""
        # Repeated cleanup cannot target a PID/PGID which may now be recycled.
        def stale_signal(*args):
            pytest.fail("gateway attempted to signal a numeric process group")
        monkeypatch.setattr(os, "killpg", stale_signal)
        await login.close()
        assert not login.alive
    finally:
        if writer is not None:
            # Release the synthetic descendant even when testing broken cleanup.
            writer.close()
            await writer.wait_closed()
        if not closed:
            await login.close()
        server.close()
        await server.wait_closed()


@pytest.mark.platforms("linux")
@pytest.mark.asyncio
async def test_cancel_during_spawn_closes_owned_group(tmp_path, monkeypatch):
    from hermes_platform import resolver

    monkeypatch.setattr(resolver, "locate_command", lambda name: SimpleNamespace(
        command=(sys.executable, "-c", "import time; time.sleep(60)")))
    spawned = asyncio.Event()
    release = asyncio.Event()
    children = []
    real_spawn = asyncio.create_subprocess_exec

    async def delayed_spawn(*args, **kwargs):
        child = await real_spawn(*args, **kwargs)
        children.append(child)
        spawned.set()
        await release.wait()
        return child

    monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed_spawn)
    starting = asyncio.create_task(ClaudeLoginProcess.start(dict(os.environ)))
    try:
        await asyncio.wait_for(spawned.wait(), 10)
        starting.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(starting, 10)
        assert children[0].returncode is not None
    finally:
        release.set()
        if not starting.done():
            starting.cancel()
        await asyncio.gather(starting, return_exceptions=True)
