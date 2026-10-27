"""Private OAuth delivery contracts: real HTTP and PTY, no model/session persistence."""
import asyncio
import logging
import secrets
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiohttp.test_utils import TestClient, TestServer

from gateway.claude_oauth_web import Handoff, PATH
from gateway.run import _profile_runtime_scope


class FakeProcess:
    alive = True
    oauth_url = "https://claude.ai/oauth/authorize?state=state"

    def __init__(self):
        self.received = []

    def deliver(self, code):
        self.received.append(code)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["success", "wrong", "csrf", "origin", "replay", "expired",
                                  "cancelled", "exited", "concurrent", "control", "oversize", "state", "missing_state", "empty_code", "extra_separator",
                                  "state_case", "state_prefix", "duplicate_state", "write_failure"])
async def test_http_capability_is_atomic_scoped_and_nonpersistent(case, tmp_path, caplog, monkeypatch):
    caplog.set_level(logging.DEBUG)
    attempt = Handoff("https://login.example.org", ("profile", "bot", "alice", "alice"))
    other = Handoff(attempt.origin, ("profile", "bot", "bob", "bob"))
    attempt.process = FakeProcess()
    other.process = FakeProcess()
    code = secrets.token_urlsafe(40) + "#state"
    headers = {"Origin": attempt.origin, "Authorization": "Bearer " + attempt.token,
               "X-CSRF-Token": attempt.csrf}
    before = list(tmp_path.rglob("*"))
    async with TestClient(TestServer(attempt.app())) as client:
        if case == "success":
            from gateway import claude_oauth_web
            probe_matches = True
            class ExternalHTTPS:
                def __init__(self, *, timeout, trust_env):
                    assert timeout.total <= 10 and trust_env is False
                async def __aenter__(self):
                    return self
                async def __aexit__(self, *args):
                    return False
                def get(self, url, *, allow_redirects, headers):
                    assert url == attempt.origin + PATH + "/health"
                    assert allow_redirects is False
                    if not probe_matches:
                        headers = {"X-Hermes-Probe": "wrong-listener"}
                    return client.get(PATH + "/health", headers=headers, allow_redirects=False)
            monkeypatch.setattr(claude_oauth_web, "ClientSession", ExternalHTTPS)
            await attempt.verify_reachable()
            probe_matches = False
            with pytest.raises(ValueError, match="disabled or unreachable"):
                await attempt.verify_reachable()
        page = await client.get(PATH + "/")
        text = await page.text()
        assert 'type="password"' in text
        assert attempt.token not in text and attempt.process.oauth_url not in text
        assert page.headers["Cache-Control"].startswith("no-store")
        assert page.headers["Referrer-Policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in page.headers["Content-Security-Policy"]
        info = await client.post(PATH + "/inspect", headers=headers, json={})
        assert (await info.json()) == {"csrf": attempt.csrf, "url": attempt.process.oauth_url}
        if case == "wrong":
            headers["Authorization"] = "Bearer " + other.token
        if case == "csrf":
            headers["X-CSRF-Token"] = other.csrf
        if case == "origin":
            headers["Origin"] = "https://attacker.example"
        if case == "expired":
            attempt.deadline = time.monotonic() - 1
        if case == "cancelled":
            attempt.invalidate()
        if case == "exited":
            attempt.process.alive = False
        if case == "state":
            code = code.removesuffix("#state") + "#wrong-state"
        if case == "missing_state":
            code = code.split("#")[0]
        if case == "empty_code":
            code = "#state"
        if case == "extra_separator":
            code = "extra#" + code
        if case == "state_case":
            code = code.removesuffix("#state") + "#State"
        if case == "state_prefix":
            code += "suffix"
        if case == "duplicate_state":
            attempt.process.oauth_url += "&state=other"
        if case == "control":
            code += "\nwhoami"
        if case == "oversize":
            code *= 200
        if case == "write_failure":
            def failed_write(value):
                raise OSError(value)
            attempt.process.deliver = failed_write
        async def submit():
            return await client.post(PATH + "/code", headers=headers, json={"code": code})
        if case == "concurrent":
            responses = await asyncio.gather(submit(), submit())
            assert sorted(r.status for r in responses) == [200, 403]
        else:
            response = await submit()
            assert response.status == (200 if case in {"success", "replay"} else
                                       400 if case in {"control", "oversize", "state", "missing_state", "empty_code",
                                                       "extra_separator", "state_case", "state_prefix", "duplicate_state"} else
                                       409 if case == "write_failure" else 403)
            assert code not in await response.text()
        if case in {"success", "replay", "concurrent"}:
            assert attempt.process.received == [code]
            assert (await submit()).status == 403
            assert (await client.post(PATH + "/inspect", headers=headers, json={})).status == 403
        else:
            assert attempt.process.received == []
            if case == "write_failure":
                assert (await submit()).status == 403
        assert other.process.received == []
        assert list(tmp_path.rglob("*")) == before
        assert code not in caplog.text and headers["Authorization"] not in caplog.text


@pytest.mark.platforms("linux")
@pytest.mark.asyncio
async def test_telegram_command_real_pty_delivery_and_disabled_cancel_paths(tmp_path, monkeypatch, caplog):
    """Real imports/config scope A→B→A; only external HTTPS/Telegram are test transports."""
    from gateway import slash_commands_claude_login as command
    from gateway.slash_commands_login import GatewayLoginCommandsMixin
    from hermes_platform import resolver
    from agent.secret_scope import is_multiplex_active, set_multiplex_active
    from hermes_cli.config import atomic_config_write
    import sys

    caplog.set_level(logging.DEBUG)
    # Fake CLI prints a real-shaped PKCE URL, waits on its actual PTY, then echoes the input.
    # The code is generated later and is never written into this fixture file.
    script = tmp_path / "fake_claude.py"
    script.write_text('''import sys
assert sys.argv[1:] == ["auth", "login"]
url = "https://claude.com/cai/oauth/authorize?code=true&response_type=code&code_challenge_method=S256&code_challenge=" + "a" * 43 + "&state=state"
print("\\x1b]8;;" + url + "\\x07" + url + "\\x1b]8;;\\x07", flush=True)
print("Paste code here if prompted: ", end="", flush=True)
value = input()
print(value, flush=True)
sys.exit(0 if value.endswith("#state") else 1)
''')
    monkeypatch.setattr(resolver, "locate_command", lambda name: SimpleNamespace(command=(sys.executable, "-u", str(script))))
    homes = [tmp_path / "a", tmp_path / "b"]
    for home in homes:
        home.mkdir()
        atomic_config_write(home / "config.yaml", {"gateway": {"claude_oauth": {
            "public_url": "https://login.example.org", "port": 8769}}})
    adapter = SimpleNamespace(config=SimpleNamespace(extra={}))
    links, clients, tasks = [], [], []
    spawn_homes = []
    original_start = command.ClaudeLoginProcess.start

    async def start_process(env):
        spawn_homes.append(env["HERMES_HOME"])
        return await original_start(env)
    monkeypatch.setattr(command.ClaudeLoginProcess, "start", start_process)

    async def start_http(self, port):
        client = TestClient(TestServer(self.app()))
        await client.start_server()
        clients.append(client)
    monkeypatch.setattr(Handoff, "start", start_http)
    reachable = True
    async def probe(self):
        if not reachable:
            raise OSError("unreachable")
        response = await clients[-1].get(PATH + "/health", headers={"X-Hermes-Probe": self.probe})
        assert await response.text() == self.probe
    monkeypatch.setattr(Handoff, "verify_reachable", probe)
    async def send(adapter, chat_id, text):
        links.append((chat_id, text))
    monkeypatch.setattr(command, "_send_private_link", send)

    class Runner(GatewayLoginCommandsMixin):
        authorized = True
        _deliver_platform_notice = AsyncMock()
        def _is_user_authorized(self, source):
            return self.authorized
        def _intake_adapter_for(self, source):
            return adapter
        def _profile_scope_for_source(self, source):
            return _profile_runtime_scope(source.home)
        def _retain_background_task(self, task):
            tasks.append(task)

    runner = Runner()
    source = SimpleNamespace(platform="telegram", chat_type="private", user_id="1", chat_id="1", home=homes[0])
    args = "claude"
    event = SimpleNamespace(source=source, get_command_args=lambda: args)
    async def wait_link(count):
        async with asyncio.timeout(10):
            while len(links) < count:
                await asyncio.sleep(.01)
    old_multiplex = is_multiplex_active()
    set_multiplex_active(True)
    try:
        for index, home in enumerate([homes[0], homes[1], homes[0]]):
            source.home = home
            reply = await runner._handle_login_command(event)
            assert "Preparing" in reply and "https:" not in reply
            await wait_link(index + 1)
            attempt = runner._claude_login_attempt
            assert attempt.owner[0] == str(home)
            assert links[-1][0] == source.chat_id
            assert attempt.token in links[-1][1]
            assert attempt.process.oauth_url not in links[-1][1]
            # Other authorized identities cannot supersede or cancel this exact PTY.
            source.user_id = source.chat_id = "2"
            args = "claude cancel"
            assert "Another" in await runner._handle_login_command(event)
            source.user_id = source.chat_id = "1"
            args = "claude"
            code = secrets.token_urlsafe(40) + "#state"
            headers = {"Origin": attempt.origin, "Authorization": "Bearer " + attempt.token,
                       "X-CSRF-Token": attempt.csrf}
            response = await clients[-1].post(PATH + "/code", headers=headers, json={"code": code})
            assert response.status == 200
            await asyncio.wait_for(tasks[-1], 10)
            assert runner._claude_login_attempt is None
            assert "completed" in runner._deliver_platform_notice.call_args.args[1]
            assert attempt.process._buffer == b"" and not attempt.process.oauth_url
            assert code not in caplog.text and headers["Authorization"] not in caplog.text
            for file in tmp_path.rglob("*"):
                if file.is_file():
                    assert code.encode() not in file.read_bytes()
        assert spawn_homes == [str(homes[0]), str(homes[1]), str(homes[0])]
        # Cancel from the owner invalidates HTTP before the task next runs.
        await runner._handle_login_command(event)
        await wait_link(4)
        attempt = runner._claude_login_attempt
        args = "claude cancel"
        assert "cancelled" in await runner._handle_login_command(event)
        assert attempt.used
        with pytest.raises(asyncio.CancelledError):
            await tasks[-1]
        assert not attempt.process.alive
        args = "claude"
        # Failed reachability never starts a child or sends a misleading URL.
        reachable = False
        await runner._handle_login_command(event)
        await tasks[-1]
        assert len(links) == 4 and len(spawn_homes) == 4
        assert "unreachable" in runner._deliver_platform_notice.call_args.args[1]
        # Cancellation before the background coroutine ever starts must release its slot too.
        await runner._handle_login_command(event)
        args = "claude cancel"
        await runner._handle_login_command(event)
        assert runner._claude_login_attempt is None
        args = "claude"
        # Shutdown uses the same invalidation and waits for the owned process to be reaped.
        reachable = True
        await runner._handle_login_command(event)
        await wait_link(5)
        attempt = runner._claude_login_attempt
        await command.close_claude_login(runner)
        assert attempt.used and not attempt.process.alive
        assert runner._claude_login_attempt is None
        runner.authorized = False
        assert "authorized" in await runner._handle_login_command(event)
        runner.authorized = True
        source.chat_type = "group"
        assert "private chat" in await runner._handle_login_command(event)
        source.chat_type = "private"
        # Unconfigured and localhost endpoints fail before any background work.
        for url in ["", "http://login.example.org", "https://localhost", "https://127.0.0.1",
                    "https://localhost.", "https://[::ffff:127.0.0.1]"]:
            atomic_config_write(homes[0] / "config.yaml", {"gateway": {"claude_oauth": {
                "public_url": url, "port": 8769}}})
            assert "disabled" in await runner._handle_login_command(event)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for client in clients:
            await client.close()
        set_multiplex_active(old_multiplex)


@pytest.mark.platforms("linux")
@pytest.mark.asyncio
@pytest.mark.parametrize("terminal_format", ["plain", "osc_bel", "osc_st"])
@pytest.mark.parametrize("endpoint,extra,accepted", [
    ("https://claude.com/cai/oauth/authorize", "", True),
    ("https://claude.ai/oauth/authorize", "", True),
    ("https://console.anthropic.com/oauth/authorize", "", True),
    ("https://platform.claude.com/oauth/authorize", "", True),
    ("https://claude.com/oauth/authorize", "", False),
    ("https://claude.ai/cai/oauth/authorize", "", False),
    ("https://claude.com.attacker.test/cai/oauth/authorize", "", False),
    ("https://user@claude.com/cai/oauth/authorize", "", False),
    ("https://claude.com:444/cai/oauth/authorize", "", False),
    ("https://claude.com:invalid/cai/oauth/authorize", "", False),
    ("https://claude.com/cai/oauth/authorize", "&state=other", False),
    ("https://claude.com/cai/oauth/authorize", "&state=", False),
    ("https://claude.com/cai/oauth/authorize", "&response_type=token", False),
    ("https://claude.com/cai/oauth/authorize", "#fragment", False),
])
async def test_cli_url_is_complete_and_bound_to_allowed_pkce_endpoint(endpoint, extra, accepted, terminal_format):
    import os
    from gateway.claude_oauth_process import ClaudeLoginProcess

    reader, writer = os.pipe()
    os.set_blocking(reader, False)
    process = ClaudeLoginProcess(SimpleNamespace(returncode=None), reader)
    url = endpoint + "?code=true&response_type=code&code_challenge_method=S256&code_challenge=" + "a" * 43 + "&state=state" + extra
    try:
        # A read boundary inside the state must never publish a truncated attempt.
        terminator = b"\x07" if terminal_format == "osc_bel" else b"\x1b\\"
        opening = b"" if terminal_format == "plain" else b"\x1b]8;;" + url.encode() + terminator
        closing = b"" if terminal_format == "plain" else b"\x1b]8;;" + terminator
        for part in [b"\x1b[32mOpen: " + opening, url[:-2].encode(), url[-2:].encode()]:
            os.write(writer, part)
            process._read()
            assert not process.oauth_url
        os.write(writer, closing + b"\x1b[0m\r\n")
        process._read()
        assert process.oauth_url == (url if accepted else "")
    finally:
        process._loop.remove_reader(reader)
        os.close(reader)
        os.close(writer)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["cancel", "expire", "exit", "claim"])
async def test_submit_rechecks_attempt_after_body_read(change):
    attempt = Handoff("https://login.example.org", ("profile", "bot", "alice", "alice"))
    attempt.process = FakeProcess()
    reading, release = asyncio.Event(), asyncio.Event()
    code = secrets.token_urlsafe(40) + "#state"
    async def read_body():
        reading.set()
        await release.wait()
        return {"code": code}
    request = SimpleNamespace(headers={"Origin": attempt.origin,
        "Authorization": "Bearer " + attempt.token, "X-CSRF-Token": attempt.csrf}, json=read_body)
    pending = asyncio.create_task(attempt.submit(request))
    try:
        await asyncio.wait_for(reading.wait(), 5)
        if change == "expire":
            attempt.deadline = time.monotonic() - 1
        elif change == "exit":
            attempt.process.alive = False
        else:
            attempt.invalidate()
            if change == "claim":
                attempt.process.deliver(code)
        release.set()
        assert (await asyncio.wait_for(pending, 5)).status == 403
        assert attempt.process.received == ([code] if change == "claim" else [])
    finally:
        release.set()
        await pending
