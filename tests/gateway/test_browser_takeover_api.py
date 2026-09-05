"""HTTP and WebSocket edge contract for authenticated takeover access."""

import asyncio
from types import SimpleNamespace

from aiohttp import WSMsgType, web
from aiohttp.test_utils import TestClient, TestServer

from gateway.browser_takeover import (
    BrowserObservation,
    BrowserTakeoverCoordinator,
    BrowserViewerAdapter,
    TakeoverScope,
    ViewerBinding,
)
from gateway.browser_takeover_access import TakeoverAccessManager
from gateway.browser_takeover_api import BrowserTakeoverAPI, TAKEOVER_COOKIE_NAME
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter


SCOPE = TakeoverScope(
    principal_id="principal-edge",
    profile_id="profile-edge",
    hermes_session_id="session-edge",
    browser_profile_id="browser-profile-edge",
    browser_session_id="browser-session-edge",
    transport_family="api_server",
)


class EdgeAdapter(BrowserViewerAdapter):
    adapter_id = "local-novnc"

    def acquire(self, scope):
        return ViewerBinding(
            adapter_id=self.adapter_id,
            viewer_session_id="viewer-edge",
            browser_profile_id=scope.browser_profile_id,
            browser_session_id=scope.browser_session_id,
            transport_family=scope.transport_family,
            display_id=":93",
            dedicated_display=True,
            cdp_endpoint="http://127.0.0.1:9224",
            vnc_endpoint="vnc://127.0.0.1:5903",
            novnc_endpoint="http://127.0.0.1:6083/vnc.html",
            novnc_websocket_endpoint="ws://127.0.0.1:6083/websockify",
            initial_observation=BrowserObservation(
                state="still_blocked",
                active_tab_id="tab-edge",
                storage_fingerprint="storage-edge",
            ),
        )

    def revoke(self, binding):
        return None

    def observe(self, binding):
        return binding.initial_observation


def _edge():
    now = [100.0]
    coordinator = BrowserTakeoverCoordinator(clock=lambda: now[0])
    grant = coordinator.acquire(SCOPE, EdgeAdapter(), ttl_seconds=300)
    manager = TakeoverAccessManager(
        coordinator,
        base_url="https://takeover.example",
        clock=lambda: now[0],
    )
    link = manager.issue(grant.lease_id, SCOPE, ttl_seconds=60)
    token = link.url.split("#claim=", 1)[1]
    return manager, grant, token


def _app(api):
    app = web.Application()
    for method, path, handler in api.routes():
        app.router.add_route(method, path, handler)
        app.router.add_route(method, f"/p/{{profile}}{path}", handler)
    return app


def test_handoff_page_is_no_store_same_origin_only_and_content_free():
    asyncio.run(_handoff_page_scenario())


async def _handoff_page_scenario():
    manager, grant, token = _edge()
    api = BrowserTakeoverAPI(manager)
    path = f"/p/profile-edge/v1/browser-takeover/{grant.lease_id}"

    async with TestClient(TestServer(_app(api))) as client:
        page = await client.get(path)
        body = await page.text()
        script = await client.get("/v1/browser-takeover/client.js")
        script_body = await script.text()
        wrong = await client.get(path.replace("profile-edge", "other"))

    assert page.status == 200
    assert page.headers["Cache-Control"] == "no-store"
    assert page.headers["Referrer-Policy"] == "no-referrer"
    assert (
        page.headers["Content-Security-Policy"]
        == "default-src 'self'; frame-ancestors 'none'"
    )
    assert token not in body
    assert token not in script_body
    assert "encodeURIComponent(path)" in script_body
    assert "127.0.0.1" not in body
    assert "http://" not in body and "https://" not in body
    assert wrong.status == 404


def test_claim_sets_secure_lease_cookie_and_rejects_wrong_origin():
    asyncio.run(_claim_cookie_scenario())


async def _claim_cookie_scenario():
    manager, grant, token = _edge()
    api = BrowserTakeoverAPI(manager)
    path = f"/p/profile-edge/v1/browser-takeover/{grant.lease_id}/claim"

    async with TestClient(TestServer(_app(api))) as client:
        wrong = await client.post(
            path,
            json={"claim": token},
            headers={"Origin": "https://evil.example"},
        )
        response = await client.post(
            path,
            json={"claim": token},
            headers={"Origin": "https://takeover.example"},
        )

    cookie = response.headers["Set-Cookie"]
    assert wrong.status == 403
    assert response.status == 204
    assert f"{TAKEOVER_COOKIE_NAME}=" in cookie
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    assert "Max-Age=60" in cookie
    assert f"Path=/p/profile-edge/v1/browser-takeover/{grant.lease_id}" in cookie


def test_viewer_http_and_websocket_use_only_authorized_exact_target():
    asyncio.run(_viewer_proxy_scenario())


async def _viewer_proxy_scenario():
    manager, grant, token = _edge()
    calls = []

    async def fetch(target, asset):
        calls.append(("http", target, asset))
        return 200, "text/html", b"viewer"

    async def bridge(request, target):
        calls.append(("ws", target))
        return web.Response(status=204)

    api = BrowserTakeoverAPI(manager, http_fetch=fetch, websocket_bridge=bridge)
    base = f"/p/profile-edge/v1/browser-takeover/{grant.lease_id}"
    async with TestClient(TestServer(_app(api))) as client:
        claim = await client.post(
            f"{base}/claim",
            json={"claim": token},
            headers={"Origin": "https://takeover.example"},
        )
        cookie = claim.headers["Set-Cookie"].split(";", 1)[0]
        denied = await client.get(
            f"{base}/viewer/vnc.html",
            headers={"Origin": "https://takeover.example"},
        )
        viewer = await client.get(
            f"{base}/viewer/vnc.html",
            headers={
                "Sec-Fetch-Site": "same-origin",
                "Cookie": cookie,
            },
        )
        cross_site = await client.get(
            f"{base}/viewer/vnc.html",
            headers={
                "Sec-Fetch-Site": "cross-site",
                "Cookie": cookie,
            },
        )
        socket = await client.get(
            f"{base}/ws",
            headers={
                "Origin": "https://takeover.example",
                "Cookie": cookie,
            },
        )
        viewer_body = await viewer.read()

    assert denied.status == 403
    assert cross_site.status == 403
    assert viewer.status == 200
    assert viewer_body == b"viewer"
    assert socket.status == 204
    assert calls[0][0] == "http"
    assert calls[0][1].http_url == "http://127.0.0.1:6083/vnc.html"
    assert calls[0][2] == "vnc.html"
    assert calls[1] == ("ws", "ws://127.0.0.1:6083/websockify")


def test_api_server_registers_takeover_routes_only_when_explicitly_enabled():
    disabled = APIServerAdapter(PlatformConfig(enabled=True))
    enabled = APIServerAdapter(
        PlatformConfig(
            enabled=True,
            extra={
                "browser_takeover": {
                    "enabled": True,
                    "public_origin": "https://takeover.example",
                }
            },
        )
    )

    disabled_paths = {path for _, path, _ in disabled._http_route_table()}
    enabled_paths = {path for _, path, _ in enabled._http_route_table()}
    assert "/v1/browser-takeover/{lease_id}" not in disabled_paths
    assert "/v1/browser-takeover/issue" in enabled_paths
    assert "/v1/browser-takeover/{lease_id}" in enabled_paths
    assert "/v1/browser-takeover/{lease_id}/viewer/{asset:.*}" in enabled_paths
    assert "/v1/browser-takeover/{lease_id}/ws" in enabled_paths
    assert enabled._browser_takeover_api is not None


def test_api_server_profile_mirror_serves_the_issued_handoff_path():
    asyncio.run(_api_server_profile_mirror_scenario())


async def _api_server_profile_mirror_scenario():
    enabled = APIServerAdapter(
        PlatformConfig(
            enabled=True,
            extra={
                "browser_takeover": {
                    "enabled": True,
                    "public_origin": "https://takeover.example",
                }
            },
        )
    )
    manager, grant, _ = _edge()
    enabled._browser_takeover_api = BrowserTakeoverAPI(manager)
    app = web.Application()
    for method, path, handler in enabled._http_route_table():
        if "browser-takeover" not in path:
            continue
        app.router.add_route(method, path, handler)
        app.router.add_route(method, f"/p/{{profile}}{path}", handler)

    issued_path = f"/p/profile-edge/v1/browser-takeover/{grant.lease_id}"
    async with TestClient(TestServer(app)) as client:
        response = await client.get(issued_path)

    assert response.status == 200


def test_default_proxy_relays_real_loopback_http_and_websocket_traffic():
    asyncio.run(_default_proxy_scenario())


async def _default_proxy_scenario():
    async def viewer_page(request):
        return web.Response(body=b"real-viewer", content_type="text/html")

    async def websockify(request):
        socket = web.WebSocketResponse()
        await socket.prepare(request)
        async for message in socket:
            if message.type == WSMsgType.BINARY:
                await socket.send_bytes(message.data)
        return socket

    upstream_app = web.Application()
    upstream_app.router.add_get("/vnc.html", viewer_page)
    upstream_app.router.add_get("/websockify", websockify)

    async with TestServer(upstream_app, host="127.0.0.1") as upstream:
        port = upstream.port

        class LiveAdapter(BrowserViewerAdapter):
            adapter_id = "live-loopback"

            def acquire(self, scope):
                return ViewerBinding(
                    adapter_id=self.adapter_id,
                    viewer_session_id="live-viewer",
                    browser_session_id=scope.browser_session_id,
                    browser_profile_id=scope.browser_profile_id,
                    transport_family=scope.transport_family,
                    display_id=":303",
                    dedicated_display=True,
                    cdp_endpoint="http://127.0.0.1:9303",
                    vnc_endpoint="vnc://127.0.0.1:5903",
                    novnc_endpoint=f"http://127.0.0.1:{port}/vnc.html",
                    novnc_websocket_endpoint=f"ws://127.0.0.1:{port}/websockify",
                    initial_observation=BrowserObservation(
                        state="still_blocked",
                        active_tab_id="tab-edge",
                    ),
                )

            def revoke(self, binding):
                return None

            def observe(self, binding):
                return binding.initial_observation

        coordinator = BrowserTakeoverCoordinator()
        grant = coordinator.acquire(SCOPE, LiveAdapter(), ttl_seconds=60)
        access = TakeoverAccessManager(coordinator, base_url="https://takeover.example")
        link = access.issue(grant.lease_id, SCOPE, ttl_seconds=60)
        token = link.url.split("#claim=", 1)[1]
        edge = BrowserTakeoverAPI(access)
        base = f"/p/profile-edge/v1/browser-takeover/{grant.lease_id}"

        async with TestClient(TestServer(_app(edge))) as client:
            claimed = await client.post(
                f"{base}/claim",
                json={"claim": token},
                headers={"Origin": "https://takeover.example"},
            )
            cookie = claimed.headers["Set-Cookie"].split(";", 1)[0]
            page = await client.get(
                f"{base}/viewer/vnc.html",
                headers={"Sec-Fetch-Site": "same-origin", "Cookie": cookie},
            )
            assert await page.read() == b"real-viewer"

            socket = await client.ws_connect(
                f"{base}/ws",
                headers={
                    "Origin": "https://takeover.example",
                    "Cookie": cookie,
                },
            )
            await socket.send_bytes(b"frame")
            message = await socket.receive(timeout=2)
            await socket.close()

        assert message.type == WSMsgType.BINARY
        assert message.data == b"frame"


def test_authenticated_issue_route_derives_complete_scope_server_side(monkeypatch):
    asyncio.run(_authenticated_issue_scenario(monkeypatch))


async def _authenticated_issue_scenario(monkeypatch):
    key = "fixture-neutral-api-key-123"
    adapter = APIServerAdapter(
        PlatformConfig(
            enabled=True,
            extra={
                "key": key,
                "browser_takeover": {
                    "enabled": True,
                    "public_origin": "https://takeover.example",
                },
            },
        )
    )
    coordinator = BrowserTakeoverCoordinator()
    scope = TakeoverScope(
        principal_id=adapter._derive_browser_control_principal("default"),
        profile_id="default",
        hermes_session_id="session-issue",
        browser_profile_id="browser-profile-issue",
        browser_session_id="browser-session-issue",
        transport_family="local-api",
    )
    grant = coordinator.acquire(scope, EdgeAdapter(), ttl_seconds=60)
    manager = TakeoverAccessManager(coordinator, base_url="https://takeover.example")
    adapter._browser_takeover_api = BrowserTakeoverAPI(manager)
    adapter._session_db = SimpleNamespace(
        get_session=lambda session_id: (
            {"id": session_id} if session_id == scope.hermes_session_id else None
        )
    )

    async def ensure_db():
        return adapter._session_db

    monkeypatch.setattr(adapter, "_ensure_session_db_async", ensure_db)
    app = web.Application()
    app.router.add_post(
        "/v1/browser-takeover/issue", adapter._handle_browser_takeover_issue
    )
    payload = {
        "lease_id": grant.lease_id,
        "session_id": scope.hermes_session_id,
        "browser_profile_id": scope.browser_profile_id,
        "browser_session_id": scope.browser_session_id,
        "ttl_seconds": 30,
        "principal_id": "attacker-supplied",
        "profile_id": "attacker-supplied",
        "transport_family": "attacker-supplied",
    }
    async with TestClient(TestServer(app)) as client:
        denied = await client.post("/v1/browser-takeover/issue", json=payload)
        issued = await client.post(
            "/v1/browser-takeover/issue",
            json=payload,
            headers={"Authorization": f"Bearer {key}"},
        )
        body = await issued.json()

    assert denied.status == 401
    assert issued.status == 201
    assert body["lease_id"] == grant.lease_id
    assert body["url"].startswith(
        f"https://takeover.example/p/default/v1/browser-takeover/{grant.lease_id}#claim="
    )
    assert "127.0.0.1" not in str(body)
    assert body["scope"] == {
        "principal_id": scope.principal_id,
        "profile_id": scope.profile_id,
        "session_id": scope.hermes_session_id,
        "browser_profile_id": scope.browser_profile_id,
        "browser_session_id": scope.browser_session_id,
        "transport_family": scope.transport_family,
    }
