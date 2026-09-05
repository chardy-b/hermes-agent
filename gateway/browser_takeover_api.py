"""Aiohttp edge for authenticated, lease-confined noVNC takeover."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit, urlunsplit

from aiohttp import ClientSession, ClientTimeout, WSCloseCode, WSMsgType, web

from gateway.browser_takeover import ViewerProxyTarget
from gateway.browser_takeover_access import (
    TAKEOVER_RESPONSE_HEADERS,
    TakeoverAccessError,
    TakeoverAccessManager,
    TakeoverCompletionFailed,
    TakeoverOriginRejected,
)


TAKEOVER_COOKIE_NAME = "__Secure-hermes-browser-takeover"
_MAX_PROXY_BODY = 4 * 1024 * 1024
_ALLOWED_ASSETS = ("vnc.html", "vnc_lite.html")
_ALLOWED_ASSET_PREFIXES = ("app/", "core/", "vendor/")

HttpFetch = Callable[[ViewerProxyTarget, str], Awaitable[tuple[int, str, bytes]]]
WebSocketBridge = Callable[[web.Request, str], Awaitable[web.StreamResponse]]

_HANDOFF_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Hermes browser takeover</title><script defer src="/v1/browser-takeover/client.js"></script></head>
<body><main><h1>Browser takeover</h1><p id="status">Claiming this browser session…</p></main></body></html>"""

_CONTROL_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Hermes browser takeover</title><script defer src="/v1/browser-takeover/client.js"></script></head>
<body><main><h1>Browser takeover</h1><p id="status">Human control is active.</p>
<iframe id="takeover-viewer" title="Browser viewer"></iframe>
<button id="takeover-done" type="button">Done</button></main></body></html>"""

_CLIENT_JS = """'use strict';
(async () => {
  const status = document.getElementById('status');
  if (location.pathname.endsWith('/control')) {
    const base = location.pathname.slice(0, -'/control'.length);
    const viewer = document.getElementById('takeover-viewer');
    const done = document.getElementById('takeover-done');
    const path = base.slice(1) + '/ws';
    viewer.src = base + '/viewer/vnc.html?autoconnect=1&path=' + encodeURIComponent(path);
    done.addEventListener('click', async () => {
      done.disabled = true;
      const response = await fetch(base + '/complete', {
        method: 'POST', credentials: 'same-origin'
      });
      if (!response.ok) {
        status.textContent = 'Browser ownership could not be returned safely.';
        return;
      }
      const report = await response.json();
      viewer.removeAttribute('src');
      status.textContent = 'Observed browser state: ' + String(report.outcome);
    });
    return;
  }
  const claim = new URLSearchParams(location.hash.slice(1)).get('claim');
  history.replaceState(null, '', location.pathname);
  if (!claim) { status.textContent = 'This takeover link is not valid.'; return; }
  const response = await fetch(location.pathname + '/claim', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    credentials: 'same-origin', body: JSON.stringify({claim})
  });
  status.textContent = response.ok ? 'Human control is active.' : 'This takeover link is not valid.';
  if (response.ok) {
    location.replace(location.pathname + '/control');
  }
})();
"""


class BrowserTakeoverAPI:
    """Map claims/cookies onto one exact loopback noVNC upstream."""

    def __init__(
        self,
        access: TakeoverAccessManager,
        *,
        http_fetch: HttpFetch | None = None,
        websocket_bridge: WebSocketBridge | None = None,
    ) -> None:
        self.access = access
        self._http_fetch = http_fetch or self._default_http_fetch
        self._websocket_bridge = websocket_bridge or self._default_websocket_bridge

    def routes(self) -> list[tuple[str, str, Callable]]:
        root = "/v1/browser-takeover/{lease_id}"
        return [
            ("GET", "/v1/browser-takeover/client.js", self.client_js),
            ("GET", root, self.page),
            ("POST", f"{root}/claim", self.claim),
            ("GET", f"{root}/control", self.control),
            ("POST", f"{root}/complete", self.complete),
            ("GET", f"{root}/viewer/{{asset:.*}}", self.viewer_asset),
            ("GET", f"{root}/ws", self.websocket),
        ]

    async def page(self, request: web.Request) -> web.Response:
        try:
            self._scope(request)
        except TakeoverAccessError:
            return self._error(404)
        return web.Response(
            text=_HANDOFF_HTML,
            content_type="text/html",
            headers=self._headers(),
        )

    async def client_js(self, request: web.Request) -> web.Response:
        return web.Response(
            text=_CLIENT_JS,
            content_type="application/javascript",
            headers=self._headers(),
        )

    async def claim(self, request: web.Request) -> web.Response:
        try:
            scope = self._scope(request)
            if request.headers.get("Origin", "") != self.access.origin:
                raise TakeoverOriginRejected("takeover origin is not allowed")
            payload = await request.json()
            if not isinstance(payload, dict) or set(payload) != {"claim"}:
                raise TakeoverAccessError("invalid claim payload")
            claim_token = payload.get("claim")
            if not isinstance(claim_token, str):
                raise TakeoverAccessError("invalid claim payload")
            cookie = self.access.claim(
                request.match_info["lease_id"],
                claim_token,
                origin=request.headers.get("Origin", ""),
                scope=scope,
            )
        except TakeoverOriginRejected:
            return self._error(403)
        except (TakeoverAccessError, ValueError, TypeError):
            return self._error(404)
        response = web.Response(status=204, headers=self._headers())
        response.set_cookie(
            TAKEOVER_COOKIE_NAME,
            cookie.value,
            path=cookie.path,
            secure=True,
            httponly=True,
            samesite="Strict",
            max_age=self.access.remaining_seconds(
                request.match_info["lease_id"], scope
            ),
        )
        return response

    async def viewer_asset(self, request: web.Request) -> web.Response:
        asset = request.match_info.get("asset", "")
        if not self._asset_allowed(asset):
            return self._error(404)
        try:
            target = self._authorize(request, allow_same_origin_navigation=True)
            status, content_type, body = await self._http_fetch(target, asset)
        except TakeoverAccessError:
            return self._error(403)
        except Exception:
            return self._error(502)
        if status != 200 or len(body) > _MAX_PROXY_BODY:
            return self._error(502)
        return web.Response(
            status=status,
            body=body,
            content_type=content_type.split(";", 1)[0],
            headers=self._headers(),
        )

    async def control(self, request: web.Request) -> web.Response:
        try:
            self._authorize(request, allow_same_origin_navigation=True)
        except TakeoverAccessError:
            return self._error(403)
        return web.Response(
            text=_CONTROL_HTML,
            content_type="text/html",
            headers=self._headers(),
        )

    async def complete(self, request: web.Request) -> web.Response:
        try:
            scope = self._scope(request, allow_terminal=True)
            origin = request.headers.get("Origin", "")
            if origin != self.access.origin:
                raise TakeoverOriginRejected("takeover origin is not allowed")
            report = await asyncio.to_thread(
                self.access.complete,
                request.match_info["lease_id"],
                request.cookies.get(TAKEOVER_COOKIE_NAME, ""),
                origin=origin,
                scope=scope,
            )
        except TakeoverOriginRejected:
            return self._error(403)
        except TakeoverCompletionFailed:
            return self._error(409)
        except TakeoverAccessError:
            return self._error(403)
        response = web.json_response(
            {
                "lease_id": report.lease_id,
                "outcome": report.outcome,
                "continuity_verified": report.continuity_verified,
                "active_tab_id": report.active_tab_id,
            },
            headers=self._headers(),
        )
        response.set_cookie(
            TAKEOVER_COOKIE_NAME,
            "",
            path=self.access.cookie_path(report.lease_id, scope),
            secure=True,
            httponly=True,
            samesite="Strict",
            max_age=0,
            expires="Thu, 01 Jan 1970 00:00:00 GMT",
        )
        return response

    async def websocket(self, request: web.Request) -> web.StreamResponse:
        try:
            target = self._authorize(request)
        except TakeoverAccessError:
            return self._error(403)
        try:
            return await self._websocket_bridge(request, target.websocket_url)
        except Exception:
            return self._error(502)

    def _scope(self, request: web.Request, *, allow_terminal: bool = False):
        profile = request.match_info.get("profile") or "default"
        return self.access.scope_for_profile(
            request.match_info["lease_id"],
            profile,
            allow_terminal=allow_terminal,
        )

    def _authorize(
        self, request: web.Request, *, allow_same_origin_navigation: bool = False
    ) -> ViewerProxyTarget:
        scope = self._scope(request)
        origin = request.headers.get("Origin", "")
        if (
            not origin
            and allow_same_origin_navigation
            and request.headers.get("Sec-Fetch-Site") == "same-origin"
        ):
            origin = self.access.origin
        return self.access.authorize(
            request.match_info["lease_id"],
            request.cookies.get(TAKEOVER_COOKIE_NAME, ""),
            origin=origin,
            scope=scope,
        )

    @staticmethod
    def _asset_allowed(asset: str) -> bool:
        return (
            asset in _ALLOWED_ASSETS
            or any(asset.startswith(prefix) for prefix in _ALLOWED_ASSET_PREFIXES)
        ) and ".." not in asset.split("/")

    @staticmethod
    def _headers() -> dict[str, str]:
        return {
            **TAKEOVER_RESPONSE_HEADERS,
            "X-Content-Type-Options": "nosniff",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        }

    @classmethod
    def _error(cls, status: int) -> web.Response:
        return web.json_response(
            {"error": {"code": "takeover_access_denied"}},
            status=status,
            headers=cls._headers(),
        )

    @staticmethod
    async def _default_http_fetch(
        target: ViewerProxyTarget, asset: str
    ) -> tuple[int, str, bytes]:
        base = urlsplit(target.http_url)
        upstream = urlunsplit((base.scheme, base.netloc, f"/{asset}", "", ""))
        timeout = ClientTimeout(total=15)
        async with ClientSession(timeout=timeout, trust_env=False) as session:
            async with session.get(upstream, allow_redirects=False) as response:
                body = await response.content.read(_MAX_PROXY_BODY + 1)
                return (
                    response.status,
                    response.headers.get("Content-Type", "application/octet-stream"),
                    body,
                )

    @classmethod
    async def _default_websocket_bridge(
        cls, request: web.Request, upstream_url: str
    ) -> web.StreamResponse:
        downstream = web.WebSocketResponse(
            max_msg_size=16 * 1024 * 1024,
            heartbeat=30,
        )
        downstream.headers.update(cls._headers())
        await downstream.prepare(request)
        timeout = ClientTimeout(total=None, sock_connect=10)
        async with ClientSession(timeout=timeout, trust_env=False) as session:
            try:
                upstream = await session.ws_connect(
                    upstream_url,
                    max_msg_size=16 * 1024 * 1024,
                    heartbeat=30,
                )
            except Exception:
                await downstream.close(
                    code=WSCloseCode.INTERNAL_ERROR,
                    message=b"viewer upstream unavailable",
                )
                return downstream
            async with upstream:

                async def to_upstream() -> None:
                    async for message in downstream:
                        if message.type == WSMsgType.BINARY:
                            await upstream.send_bytes(message.data)
                        elif message.type == WSMsgType.TEXT:
                            await upstream.send_str(message.data)
                        elif message.type in {WSMsgType.CLOSE, WSMsgType.ERROR}:
                            break

                async def to_downstream() -> None:
                    async for message in upstream:
                        if message.type == WSMsgType.BINARY:
                            await downstream.send_bytes(message.data)
                        elif message.type == WSMsgType.TEXT:
                            await downstream.send_str(message.data)
                        elif message.type in {WSMsgType.CLOSE, WSMsgType.ERROR}:
                            break

                tasks = [
                    asyncio.create_task(to_upstream()),
                    asyncio.create_task(to_downstream()),
                ]
                done, pending = await asyncio.wait(
                    tasks, return_when=asyncio.FIRST_COMPLETED
                )
                for task in pending:
                    task.cancel()
                await asyncio.gather(*done, *pending, return_exceptions=True)
        await downstream.close()
        return downstream
