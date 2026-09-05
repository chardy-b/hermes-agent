"""Security contract for browser takeover claims and cookies."""

import base64
import threading
from dataclasses import replace
from urllib.parse import urlsplit

import pytest

from gateway.browser_takeover import (
    BrowserObservation,
    BrowserTakeoverCoordinator,
    BrowserViewerAdapter,
    TakeoverScope,
    ViewerBinding,
)
from gateway.browser_takeover_access import (
    TAKEOVER_RESPONSE_HEADERS,
    TakeoverAccessManager,
    TakeoverClaimInvalid,
    TakeoverOriginRejected,
    TakeoverScopeRejected,
)


SCOPE = TakeoverScope(
    principal_id="principal-a",
    profile_id="profile-a",
    hermes_session_id="session-a",
    browser_profile_id="browser-profile-a",
    browser_session_id="browser-session-a",
    transport_family="api_server",
)


class Adapter(BrowserViewerAdapter):
    adapter_id = "local-novnc"

    def acquire(self, scope):
        return ViewerBinding(
            adapter_id=self.adapter_id,
            viewer_session_id="viewer-a",
            browser_profile_id=scope.browser_profile_id,
            browser_session_id=scope.browser_session_id,
            transport_family=scope.transport_family,
            display_id=":91",
            dedicated_display=True,
            cdp_endpoint="http://127.0.0.1:9222",
            vnc_endpoint="vnc://127.0.0.1:5901",
            novnc_endpoint="http://127.0.0.1:6081/vnc.html",
            novnc_websocket_endpoint="ws://127.0.0.1:6081/websockify",
            initial_observation=BrowserObservation(
                state="still_blocked",
                active_tab_id="tab-a",
                storage_fingerprint="storage-a",
            ),
        )

    def revoke(self, binding):
        return None

    def observe(self, binding):
        return binding.initial_observation


def _setup():
    now = [100.0]
    coordinator = BrowserTakeoverCoordinator(clock=lambda: now[0])
    grant = coordinator.acquire(SCOPE, Adapter(), ttl_seconds=300)
    manager = TakeoverAccessManager(
        coordinator,
        base_url="https://takeover.example",
        clock=lambda: now[0],
    )
    link = manager.issue(grant.lease_id, SCOPE, ttl_seconds=60)
    token = urlsplit(link.url).fragment.removeprefix("claim=")
    return now, coordinator, grant, manager, link, token


def test_link_uses_fragment_entropy_and_stores_only_digest():
    _, _, grant, manager, link, token = _setup()

    assert urlsplit(link.url).query == ""
    assert len(base64.urlsafe_b64decode(token + "==")) >= 32
    record = manager.inspect(grant.lease_id)
    assert record.claim_digest
    assert record.cookie_digest is None
    assert not hasattr(record, "claim_token")
    assert token not in repr(manager)
    assert token not in repr(link)
    assert TAKEOVER_RESPONSE_HEADERS == {
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    }


def test_claim_is_single_use_and_cookie_supports_reconnect():
    _, _, grant, manager, _, token = _setup()
    cookie = manager.claim(
        grant.lease_id,
        token,
        origin="https://takeover.example",
        scope=SCOPE,
    )

    assert cookie.secure is True
    assert cookie.http_only is True
    assert cookie.same_site == "Strict"
    assert cookie.path == f"/p/profile-a/v1/browser-takeover/{grant.lease_id}"
    with pytest.raises(TakeoverClaimInvalid):
        manager.claim(
            grant.lease_id,
            token,
            origin="https://takeover.example",
            scope=SCOPE,
        )
    first = manager.authorize(
        grant.lease_id,
        cookie.value,
        origin="https://takeover.example",
        scope=SCOPE,
    )
    second = manager.authorize(
        grant.lease_id,
        cookie.value,
        origin="https://takeover.example",
        scope=SCOPE,
    )
    assert first == second
    assert first.websocket_url == "ws://127.0.0.1:6081/websockify"
    assert "127.0.0.1" not in repr(first)
    assert cookie.value not in repr(cookie)


def test_access_record_history_is_bounded_and_prunes_revoked_records():
    coordinator = BrowserTakeoverCoordinator()
    manager = TakeoverAccessManager(
        coordinator,
        base_url="https://takeover.example",
        max_records=2,
    )
    lease_ids = []
    for index in range(3):
        scope = replace(
            SCOPE,
            browser_session_id=f"browser-session-{index}",
        )
        grant = coordinator.acquire(scope, Adapter(), ttl_seconds=60)
        manager.issue(grant.lease_id, scope, ttl_seconds=60)
        manager.revoke(grant.lease_id, scope)
        coordinator.complete(grant.lease_id, scope)
        lease_ids.append(grant.lease_id)

    assert manager.record_count == 2
    with pytest.raises(TakeoverClaimInvalid):
        manager.inspect(lease_ids[0])


def test_wrong_origin_scope_and_expiry_fail_closed():
    now, _, grant, manager, _, token = _setup()
    with pytest.raises(TakeoverOriginRejected):
        manager.claim(grant.lease_id, token, origin="https://evil.example", scope=SCOPE)
    with pytest.raises(TakeoverScopeRejected):
        manager.claim(
            grant.lease_id,
            token,
            origin="https://takeover.example",
            scope=replace(SCOPE, profile_id="profile-b"),
        )
    now[0] = 161.0
    with pytest.raises(TakeoverClaimInvalid):
        manager.claim(
            grant.lease_id,
            token,
            origin="https://takeover.example",
            scope=SCOPE,
        )


def test_concurrent_claim_has_one_winner():
    _, _, grant, manager, _, token = _setup()
    barrier = threading.Barrier(3)
    successes = []
    failures = []

    def claim():
        barrier.wait()
        try:
            successes.append(
                manager.claim(
                    grant.lease_id,
                    token,
                    origin="https://takeover.example",
                    scope=SCOPE,
                )
            )
        except TakeoverClaimInvalid as exc:
            failures.append(exc)

    threads = [threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(2)

    assert len(successes) == 1
    assert len(failures) == 1


def test_revocation_invalidates_cookie_before_viewer_reuse():
    _, _, grant, manager, _, token = _setup()
    cookie = manager.claim(
        grant.lease_id,
        token,
        origin="https://takeover.example",
        scope=SCOPE,
    )
    manager.revoke(grant.lease_id, SCOPE)

    with pytest.raises(TakeoverClaimInvalid):
        manager.authorize(
            grant.lease_id,
            cookie.value,
            origin="https://takeover.example",
            scope=SCOPE,
        )
