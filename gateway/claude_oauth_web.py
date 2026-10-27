"""Ephemeral capability form for one owned Claude login, served only on loopback.

The reverse proxy must disable request-body/header logging and caching. Capabilities use a
fragment, never a URL path/query; the code only crosses a bounded POST and the owned PTY.
"""
from __future__ import annotations

import hmac
import ipaddress
import re
import secrets
import time
from urllib.parse import parse_qs, urlsplit

from aiohttp import ClientSession, ClientTimeout, web

PATH = "/claude-oauth"
TTL = 300
DISABLED = (
    "Claude login handoff is disabled or unreachable. Configure gateway.claude_oauth.public_url "
    "as a phone-reachable HTTPS origin and proxy /claude-oauth/ to the configured loopback port "
    "(default 8769), with request body/header logging and caching disabled. "
    "See website/docs/user-guide/claude-telegram-oauth.md. Never paste a code into Telegram."
)
HEADERS = {
    "Cache-Control": "no-store, max-age=0", "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; connect-src 'self'; "
                               "form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
    "X-Frame-Options": "DENY", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Strict-Transport-Security": "max-age=31536000",
}
HTML = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport"
content="width=device-width, initial-scale=1"><title>Claude Code login</title></head><body>
<h1>Claude Code login</h1><p id="status">Checking this private login attempt…</p>
<a id="authorize" hidden target="_blank" rel="noreferrer noopener">Authorize with Claude</a>
<form id="codeform" hidden autocomplete="off"><p>Paste the code from Claude here, never in Telegram.</p>
<label>Authorization code <input id="code" type="password" autocomplete="off" maxlength="512"
spellcheck="false" autocapitalize="none" required></label><button>Submit once</button></form>
<script src="/claude-oauth/form.js" defer></script></body></html>"""
JS = """'use strict';
(async () => {
  let token = location.hash.slice(1);
  history.replaceState(null, '', location.pathname);
  const status = document.getElementById('status');
  const form = document.getElementById('codeform');
  const input = document.getElementById('code');
  let csrf = '';
  const call = (path, body) => fetch('/claude-oauth/' + path, {
    method: 'POST', cache: 'no-store', credentials: 'omit', redirect: 'error',
    referrerPolicy: 'no-referrer', headers: {'Authorization': 'Bearer ' + token,
    'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, body: JSON.stringify(body)
  });
  try {
    if (!isSecureContext || location.protocol !== 'https:' || !token) throw Error();
    const response = await call('inspect', {});
    if (!response.ok) throw Error();
    const data = await response.json(); csrf = data.csrf;
    const link = document.getElementById('authorize'); link.href = data.url; link.hidden = false;
    form.hidden = false; status.textContent = 'Authorize, then submit within five minutes. Do not share this page.';
    form.onsubmit = async event => {
      event.preventDefault(); form.hidden = true; link.hidden = true;
      let code = input.value.trim(); input.value = '';
      try {
        const pending = call('code', {code}); code = '';
        const result = await pending;
        status.textContent = result.ok ? 'Code delivered. Check Telegram for the login result.' :
          'Attempt rejected. Start again from Telegram.';
      } catch { status.textContent = 'Delivery uncertain. Start again from Telegram.'; }
      finally { code = ''; token = ''; csrf = ''; }
    };
  } catch { token = ''; status.textContent = 'Unavailable or expired. Start again from Telegram.'; }
})();"""


def configured_origin(settings):
    raw = settings.get("public_url", "")
    parsed = urlsplit(raw)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            or parsed.hostname.lower().rstrip(".") == "localhost"
            or parsed.hostname.lower().rstrip(".").endswith(".localhost")):
        raise ValueError(DISABLED)
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address is not None and (address.is_loopback or address.is_unspecified or address.is_link_local):
        raise ValueError(DISABLED)
    hostname = parsed.hostname.lower()
    host = "[" + hostname + "]" if ":" in hostname else hostname
    port = parsed.port
    return "https://" + host + (":" + str(port) if port not in {None, 443} else "")


class Handoff:
    """All mutations run on one asyncio loop; claim + PTY write have no await between them."""
    def __init__(self, origin, owner):
        self.origin = origin
        self.owner = owner
        self.token = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(32)
        self.probe = secrets.token_urlsafe(32)
        self.deadline = time.monotonic() + TTL
        self.process = None
        self.used = False
        self.runner = None

    def invalidate(self):
        self.used = True
        self.token = self.csrf = ""

    def valid(self, request):
        return (not self.used and time.monotonic() < self.deadline
                and self.process is not None and self.process.alive
                and request.headers.get("Origin") == self.origin
                and hmac.compare_digest(request.headers.get("Authorization", ""), "Bearer " + self.token))

    def app(self):
        @web.middleware
        async def safe_response(request, handler):
            try:
                response = await handler(request)
            except (web.HTTPException, ValueError, UnicodeError):
                response = web.Response(status=400, text="Request rejected")
            except Exception:
                # No exception rendering/logging: frameworks can include request bodies in errors.
                response = web.Response(status=503, text="Login unavailable")
            response.headers.update(HEADERS)
            return response

        app = web.Application(client_max_size=2048, middlewares=[safe_response])
        app.router.add_get(PATH + "/", self.page)
        app.router.add_get(PATH + "/form.js", self.script)
        app.router.add_get(PATH + "/health", self.health)
        app.router.add_post(PATH + "/inspect", self.inspect)
        app.router.add_post(PATH + "/code", self.submit)
        return app

    async def page(self, request):
        return web.Response(text=HTML, content_type="text/html")

    async def script(self, request):
        return web.Response(text=JS, content_type="application/javascript")

    async def health(self, request):
        supplied = request.headers.get("X-Hermes-Probe", "")
        if not hmac.compare_digest(supplied, self.probe):
            return web.Response(status=404)
        return web.Response(text=self.probe)

    async def inspect(self, request):
        if not self.valid(request):
            return web.Response(status=403, text="Attempt unavailable")
        return web.json_response({"csrf": self.csrf, "url": self.process.oauth_url})

    async def submit(self, request):
        if (not self.valid(request) or not hmac.compare_digest(
                request.headers.get("X-CSRF-Token", ""), self.csrf)):
            return web.Response(status=403, text="Attempt unavailable")
        data = await request.json()
        code = data.get("code") if isinstance(data, dict) else None
        # Exclude newlines, terminal controls, URLs, and arbitrary stdin protocols.
        if not isinstance(code, str) or len(code) > 512 or not re.fullmatch(r"[A-Za-z0-9_.-]+#[A-Za-z0-9_.-]+", code):
            return web.Response(status=400, text="Invalid code")
        states = parse_qs(urlsplit(self.process.oauth_url).query, keep_blank_values=True).get("state", [])
        if len(states) != 1 or not states[0] or not hmac.compare_digest(code.split("#")[1], states[0]):
            return web.Response(status=400, text="Code belongs to a different login")
        # Recheck after the body await: cancel, expiry, exit or another POST may have won.
        if not self.valid(request):
            return web.Response(status=403, text="Attempt unavailable")
        self.invalidate()
        try:
            self.process.deliver(code)
        except Exception:
            return web.Response(status=409, text="Delivery failed; start again")
        finally:
            code = None
            data.clear()
        return web.Response(text="Delivered")

    async def start(self, port):
        self.runner = web.AppRunner(self.app(), access_log=None, shutdown_timeout=1)
        await self.runner.setup()
        await web.TCPSite(self.runner, "127.0.0.1", port).start()

    async def verify_reachable(self):
        # Probe the exact listener, with certificate validation and without redirects or env proxies.
        async with ClientSession(timeout=ClientTimeout(total=8), trust_env=False) as client:
            async with client.get(self.origin + PATH + "/health", allow_redirects=False,
                                  headers={"X-Hermes-Probe": self.probe}) as response:
                if response.status != 200 or await response.content.read(128) != self.probe.encode():
                    raise ValueError(DISABLED)

    async def close(self):
        self.invalidate()
        try:
            if self.process is not None:
                await self.process.close()
        finally:
            if self.runner is not None:
                await self.runner.cleanup()
