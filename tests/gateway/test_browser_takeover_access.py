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


def test_human_completion_revokes_cookie_and_is_idempotent():
    class CountingAdapter(Adapter):
        def __init__(self):
            self.revoke_calls = 0
            self.manager: TakeoverAccessManager | None = None
            self.cookie_value = ""
            self.lease_id = ""

        def revoke(self, binding):
            self.revoke_calls += 1

        def observe(self, binding):
            assert self.manager is not None
            with pytest.raises(TakeoverClaimInvalid):
                self.manager.authorize(
                    self.lease_id,
                    self.cookie_value,
                    origin="https://takeover.example",
                    scope=SCOPE,
                )
            return super().observe(binding)

    now = [100.0]
    coordinator = BrowserTakeoverCoordinator(clock=lambda: now[0])
    adapter = CountingAdapter()
    grant = coordinator.acquire(SCOPE, adapter, ttl_seconds=60)
    manager = TakeoverAccessManager(
        coordinator,
        base_url="https://takeover.example",
        clock=lambda: now[0],
    )
    link = manager.issue(grant.lease_id, SCOPE, ttl_seconds=60)
    token = urlsplit(link.url).fragment.removeprefix("claim=")
    cookie = manager.claim(
        grant.lease_id,
        token,
        origin="https://takeover.example",
        scope=SCOPE,
    )
    adapter.manager = manager
    adapter.cookie_value = cookie.value
    adapter.lease_id = grant.lease_id

    first = manager.complete(
        grant.lease_id,
        cookie.value,
        origin="https://takeover.example",
        scope=SCOPE,
    )
    second = manager.complete(
        grant.lease_id,
        cookie.value,
        origin="https://takeover.example",
        scope=SCOPE,
    )

    assert first == second
    assert first.outcome == "still_blocked"
    assert first.continuity_verified is True
    assert adapter.revoke_calls == 1
    with pytest.raises(TakeoverClaimInvalid):
        manager.authorize(
            grant.lease_id,
            cookie.value,
            origin="https://takeover.example",
            scope=SCOPE,
        )


def test_expired_cookie_reports_expired_without_releasing_agent_input():
    clock = [100.0]
    coordinator = BrowserTakeoverCoordinator(clock=lambda: 100.0)
    grant = coordinator.acquire(SCOPE, Adapter(), ttl_seconds=300)
    manager = TakeoverAccessManager(
        coordinator,
        base_url="https://takeover.example",
        clock=lambda: clock[0],
    )
    link = manager.issue(grant.lease_id, SCOPE, ttl_seconds=10)
    token = urlsplit(link.url).fragment.removeprefix("claim=")
    cookie = manager.claim(
        grant.lease_id,
        token,
        origin="https://takeover.example",
        scope=SCOPE,
    )
    clock[0] = 111.0

    report = manager.complete(
        grant.lease_id,
        cookie.value,
        origin="https://takeover.example",
        scope=SCOPE,
    )

    assert report.outcome == "expired"
    assert report.continuity_verified is False
    assert report.active_tab_id == ""
    assert (
        manager.complete(
            grant.lease_id,
            cookie.value,
            origin="https://takeover.example",
            scope=SCOPE,
        )
        == report
    )
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
    with pytest.raises(TakeoverClaimInvalid):
        manager.authorize(
            grant.lease_id,
            cookie.value,
            origin="https://takeover.example",
            scope=SCOPE,
        )


def test_concurrent_human_completion_revokes_once_and_returns_one_report():
    class BlockingAdapter(Adapter):
        def __init__(self):
            self.revoke_calls = 0
            self.entered = threading.Event()
            self.release = threading.Event()

        def revoke(self, binding):
            self.revoke_calls += 1
            self.entered.set()
            assert self.release.wait(2)

    coordinator = BrowserTakeoverCoordinator()
    adapter = BlockingAdapter()
    grant = coordinator.acquire(SCOPE, adapter, ttl_seconds=60)
    manager = TakeoverAccessManager(
        coordinator,
        base_url="https://takeover.example",
        completion_wait_timeout=2,
    )
    link = manager.issue(grant.lease_id, SCOPE, ttl_seconds=60)
    token = urlsplit(link.url).fragment.removeprefix("claim=")
    cookie = manager.claim(
        grant.lease_id,
        token,
        origin="https://takeover.example",
        scope=SCOPE,
    )
    reports = []
    errors = []

    def finish():
        try:
            reports.append(
                manager.complete(
                    grant.lease_id,
                    cookie.value,
                    origin="https://takeover.example",
                    scope=SCOPE,
                )
            )
        except Exception as exc:
            errors.append(exc)

    first = threading.Thread(target=finish)
    second = threading.Thread(target=finish)
    first.start()
    assert adapter.entered.wait(2)
    second.start()
    adapter.release.set()
    first.join(2)
    second.join(2)

    assert errors == []
    assert len(reports) == 2
    assert reports[0] == reports[1]
    assert adapter.revoke_calls == 1


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
