"""Private Claude login PTY. Never register its output with terminal tools or session storage."""
from __future__ import annotations

import asyncio
import errno
import os
import re
import signal
from urllib.parse import parse_qs, urlsplit


class ClaudeLoginProcess:
    def __init__(self, process, master):
        self.process = process
        self.master = master
        self.oauth_url = ""
        self._buffer = bytearray()
        self._ready = asyncio.Event()
        self._loop = asyncio.get_running_loop()
        self._loop.add_reader(master, self._read)

    @classmethod
    async def start(cls, env):
        import pty
        import termios
        from hermes_platform.resolver import locate_command

        command = locate_command("claude").command
        if not command:
            raise RuntimeError("Claude Code CLI is not installed")
        master, slave = pty.openpty()
        try:
            attrs = termios.tcgetattr(slave)
            attrs[3] &= ~(termios.ECHO | termios.ECHONL)
            termios.tcsetattr(slave, termios.TCSANOW, attrs)
            os.set_blocking(master, False)
            spawning = asyncio.create_task(asyncio.create_subprocess_exec(
                *command, "auth", "login", stdin=slave, stdout=slave, stderr=slave,
                env=env, start_new_session=True,
            ))
            try:
                process = await asyncio.shield(spawning)
            except asyncio.CancelledError:
                # Cancellation during exec must not orphan a child that is still being created.
                process = await spawning
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                await process.wait()
                raise
        except BaseException:
            os.close(master)
            raise
        finally:
            os.close(slave)
        return cls(process, master)

    @property
    def alive(self):
        return self.process.returncode is None

    def _read(self):
        try:
            chunk = os.read(self.master, 4096)
        except BlockingIOError:
            return
        except OSError as exc:
            if exc.errno != errno.EIO:
                raise
            chunk = b""
        if not chunk:
            self._loop.remove_reader(self.master)
            self._ready.set()
            return
        # After finding the URL, discard everything, including application-level input echo.
        if self.oauth_url:
            return
        self._buffer.extend(chunk)
        if len(self._buffer) > 32768:
            self._buffer.clear()
            self._ready.set()
            return
        # Claude emits OSC 8 hyperlinks as well as CSI styling. Keep the visible URL,
        # not the hidden hyperlink target, and wait for its trailing whitespace.
        text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", self._buffer.decode(errors="replace"))
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
        for match in re.finditer(r"https://[^\s<>\x1b]+(?=\s)", text):
            url = match.group()
            try:
                parsed = urlsplit(url)
                port = parsed.port
                query = parse_qs(parsed.query, keep_blank_values=True)
            except ValueError:
                continue
            paths = {
                "claude.com": {"/cai/oauth/authorize", "/cai/oauth/authorize/"},
                "claude.ai": {"/oauth/authorize", "/oauth/authorize/"},
                "console.anthropic.com": {"/oauth/authorize", "/oauth/authorize/"},
                "platform.claude.com": {"/oauth/authorize", "/oauth/authorize/"},
            }
            if (parsed.path in paths.get(parsed.hostname, set())
                    and parsed.username is None and port in {None, 443}
                    and not parsed.fragment
                    and query.get("code_challenge_method") == ["S256"]
                    and query.get("response_type") == ["code"]
                    and len(query.get("code_challenge", [])) == 1
                    and re.fullmatch(r"[A-Za-z0-9_-]{43}", query["code_challenge"][0])
                    and len(query.get("state", [])) == 1
                    and re.fullmatch(r"[A-Za-z0-9_.-]+", query["state"][0])):
                self.oauth_url = url
                self._buffer.clear()
                self._ready.set()
                return

    async def wait_ready(self):
        await asyncio.wait_for(self._ready.wait(), 30)
        if not self.oauth_url or not self.alive:
            raise RuntimeError("Claude did not offer a supported PKCE login")

    def deliver(self, code):
        """One bounded write, on the owning event loop, with no await/cancellation gap."""
        if not self.alive:
            raise RuntimeError("Login exited")
        import termios
        attrs = termios.tcgetattr(self.master)
        attrs[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(self.master, termios.TCSANOW, attrs)
        data = code.encode("ascii") + b"\n"
        if os.write(self.master, data) != len(data):
            raise RuntimeError("Incomplete login input")

    async def wait(self):
        return await self.process.wait()

    async def close(self):
        self._loop.remove_reader(self.master)
        self._buffer.clear()
        self.oauth_url = ""
        # Kill the owned session's children too (e.g. a browser opener), never a PID from a request.
        if self.alive:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        await self.process.wait()
        os.close(self.master)
