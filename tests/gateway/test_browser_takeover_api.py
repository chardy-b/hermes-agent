"""HTTP and WebSocket edge contract for authenticated takeover access."""

import asyncio
from types import SimpleNamespace
from urllib.parse import urlsplit

from aiohttp import WSMsgType, web
from aiohttp.test_utils import TestClient, TestServer
import pytest

from gateway.browser_takeover import (
    BrowserObservation,
    BrowserTakeoverCoordinator,
    BrowserViewerAdapter,
    TakeoverScope,
    ViewerBinding,
)
from gateway.browser_takeover_access import TakeoverAccessManager
from gateway.browser_takeover_api import BrowserTakeoverAPI, TAKEOVER_COOKIE_NAME
from gateway.browser_takeover_service import (
    get_browser_takeover_service,
    install_browser_takeover_service,
)
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter


@pytest.fixture(autouse=True)
def _clear_takeover_service_registry():
    install_browser_takeover_service(None)
    yield
    install_browser_takeover_service(None)


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


def test_human_done_route_returns_only_observed_state_and_revokes_access():
    asyncio.run(_human_done_scenario())


async def _human_done_scenario():
    manager, grant, token = _edge()
    api = BrowserTakeoverAPI(manager)
    base = f"/p/profile-edge/v1/browser-takeover/{grant.lease_id}"
    async with TestClient(TestServer(_app(api))) as client:
        claimed = await client.post(
            f"{base}/claim",
            json={"claim": token},
            headers={"Origin": "https://takeover.example"},
        )
        cookie = claimed.headers["Set-Cookie"].split(";", 1)[0]
        control = await client.get(
            f"{base}/control",
            headers={"Sec-Fetch-Site": "same-origin", "Cookie": cookie},
        )
        control_body = await control.text()
        wrong_origin = await client.post(
            f"{base}/complete",
            headers={"Origin": "https://evil.example", "Cookie": cookie},
        )
        wrong_profile = await client.post(
            f"{base.replace('profile-edge', 'other')}/complete",
            headers={
                "Origin": "https://takeover.example",
                "Cookie": cookie,
            },
        )
        done = await client.post(
            f"{base}/complete",
            headers={
                "Origin": "https://takeover.example",
                "Cookie": cookie,
            },
        )
        done_body = await done.json()
        stale_viewer = await client.get(
            f"{base}/viewer/vnc.html",
            headers={"Sec-Fetch-Site": "same-origin", "Cookie": cookie},
        )
        duplicate = await client.post(
            f"{base}/complete",
            headers={
                "Origin": "https://takeover.example",
                "Cookie": cookie,
            },
        )
        duplicate_body = await duplicate.json()
        forged = await client.post(
            f"{base}/complete",
            headers={
                "Origin": "https://takeover.example",
                "Cookie": f"{TAKEOVER_COOKIE_NAME}=forged",
            },
        )

    assert control.status == 200
    assert 'id="takeover-done"' in control_body
    assert 'id="takeover-viewer"' in control_body
    assert token not in control_body
    assert wrong_origin.status == 403
    assert wrong_profile.status == 403
    assert done.status == 200
    assert done_body == {
        "lease_id": grant.lease_id,
        "outcome": "still_blocked",
        "continuity_verified": True,
        "active_tab_id": "tab-edge",
    }
    assert "Max-Age=0" in done.headers["Set-Cookie"]
    assert stale_viewer.status == 403
    assert duplicate.status == 200
    assert duplicate_body == done_body
    assert forged.status == 403


def test_expired_done_reports_expired_without_releasing_agent_input():
    asyncio.run(_expired_done_scenario())


async def _expired_done_scenario():
    clock = [100.0]
    coordinator = BrowserTakeoverCoordinator(clock=lambda: 100.0)
    grant = coordinator.acquire(SCOPE, EdgeAdapter(), ttl_seconds=300)
    manager = TakeoverAccessManager(
        coordinator,
        base_url="https://takeover.example",
        clock=lambda: clock[0],
    )
    token = urlsplit(
        manager.issue(grant.lease_id, SCOPE, ttl_seconds=10).url
    ).fragment.removeprefix("claim=")
    async with TestClient(TestServer(_app(BrowserTakeoverAPI(manager)))) as client:
        claim = await client.post(
            f"/p/{SCOPE.profile_id}/v1/browser-takeover/{grant.lease_id}/claim",
            json={"claim": token},
            headers={"Origin": "https://takeover.example"},
        )
        cookie = claim.headers["Set-Cookie"].split(";", 1)[0]
        clock[0] = 111.0
        done = await client.post(
            f"/p/{SCOPE.profile_id}/v1/browser-takeover/{grant.lease_id}/complete",
            headers={"Origin": "https://takeover.example", "Cookie": cookie},
        )
        payload = await done.json()

    assert done.status == 200
    assert payload == {
        "lease_id": grant.lease_id,
        "outcome": "expired",
        "continuity_verified": False,
        "active_tab_id": "",
    }
    assert (
        coordinator.guard_browser_action(
            principal_id=SCOPE.principal_id,
            profile_id=SCOPE.profile_id,
            hermes_session_id=SCOPE.hermes_session_id,
            browser_profile_id=SCOPE.browser_profile_id,
            browser_session_id=SCOPE.browser_session_id,
            transport_family=SCOPE.transport_family,
        )
        is not None
    )


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
    assert "/v1/browser-takeover/{lease_id}/control" in enabled_paths
    assert "/v1/browser-takeover/{lease_id}/complete" in enabled_paths
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
        "reason": "raw CAPTCHA prompt from the page",
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
    assert body["status"] == "human_assist_required"
    assert body["done_label"] == "Done"
    assert body["reason"] == "human_input_required"
    assert "raw CAPTCHA" not in str(body)
    assert body["lease_id"] == grant.lease_id
    assert body["url"].startswith(
        f"https://takeover.example/p/default/v1/browser-takeover/{grant.lease_id}#claim="
    )
    assert "127.0.0.1" not in str(body)
    assert body["scope"] == {
        "principal_id": scope.principal_id,
        "profile_id": scope.profile_id,
        "hermes_session_id": scope.hermes_session_id,
        "session_id": scope.hermes_session_id,
        "browser_profile_id": scope.browser_profile_id,
        "browser_session_id": scope.browser_session_id,
        "transport_family": scope.transport_family,
    }


def test_authenticated_issue_route_acquires_configured_camofox_through_coordinator(
    monkeypatch,
):
    asyncio.run(_authenticated_camofox_acquire_scenario(monkeypatch))


async def _authenticated_camofox_acquire_scenario(monkeypatch):
    from tools import browser_camofox

    key = "fixture-neutral-api-key-123"
    coordinator = BrowserTakeoverCoordinator()
    monkeypatch.setattr(
        "gateway.browser_takeover.get_browser_takeover_coordinator",
        lambda: coordinator,
    )
    adapter = APIServerAdapter(
        PlatformConfig(
            enabled=True,
            extra={
                "key": key,
                "browser_takeover": {
                    "enabled": True,
                    "public_origin": "https://takeover.example",
                    "adapter": "camofox-vnc",
                },
            },
        )
    )
    session_id = "session-camofox"
    cache_key = browser_camofox._session_cache_key(session_id, "default")
    with browser_camofox._sessions_lock:
        browser_camofox._sessions[cache_key] = {
            "user_id": "managed-profile-user",
            "tab_id": "managed-tab",
            "session_key": "task-managed",
            "managed": True,
            "adopt_existing_tab": False,
        }
    browser_camofox._vnc_url = "http://localhost:6087"
    browser_camofox._vnc_url_checked = True
    monkeypatch.setattr(browser_camofox, "check_camofox_available", lambda: True)
    adapter._session_db = SimpleNamespace(
        get_session=lambda requested: (
            {"id": requested} if requested == session_id else None
        )
    )

    async def ensure_db():
        return adapter._session_db

    monkeypatch.setattr(adapter, "_ensure_session_db_async", ensure_db)
    app = web.Application()
    app.router.add_post(
        "/v1/browser-takeover/issue", adapter._handle_browser_takeover_issue
    )
    try:
        async with TestClient(TestServer(app)) as client:
            issued = await client.post(
                "/v1/browser-takeover/issue",
                json={
                    "session_id": session_id,
                    "ttl_seconds": 30,
                    "browser_profile_id": "attacker-supplied",
                    "browser_session_id": "attacker-supplied",
                },
                headers={"Authorization": f"Bearer {key}"},
            )
            body = await issued.json()

        assert issued.status == 201
        assert body["status"] == "human_assist_required"
        assert body["adapter_id"] == "camofox-vnc"
        assert body["scope"]["session_id"] == session_id
        assert body["scope"]["browser_session_id"] == session_id
        assert body["scope"]["browser_profile_id"] != "attacker-supplied"
        scope = TakeoverScope(
            principal_id=body["scope"]["principal_id"],
            profile_id=body["scope"]["profile_id"],
            hermes_session_id=body["scope"]["session_id"],
            browser_profile_id=body["scope"]["browser_profile_id"],
            browser_session_id=body["scope"]["browser_session_id"],
            transport_family=body["scope"]["transport_family"],
        )
        blocked = coordinator.guard_browser_action(
            principal_id=scope.principal_id,
            profile_id=scope.profile_id,
            hermes_session_id=scope.hermes_session_id,
            browser_profile_id=scope.browser_profile_id,
            browser_session_id=scope.browser_session_id,
            transport_family=scope.transport_family,
        )
        assert blocked is not None
        assert blocked["ownership"] == "human"
        target = coordinator.viewer_proxy_target(body["lease_id"], scope)
        assert target.adapter_id == "camofox-vnc"
        assert get_browser_takeover_service() is adapter._browser_takeover_service
        assert "6087" not in str(body)
        assert "managed-tab" not in str(body)
    finally:
        await adapter.disconnect()
        assert get_browser_takeover_service() is None
        coordinator.reset()
        with browser_camofox._sessions_lock:
            browser_camofox._sessions.pop(cache_key, None)
