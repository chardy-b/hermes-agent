"""Behavior tests for exclusive browser takeover."""

import threading
from dataclasses import replace

import pytest

from gateway.browser_takeover import (
    BrowserObservation,
    BrowserTakeoverCoordinator,
    BrowserViewerAdapter,
    TakeoverConflict,
    TakeoverExpired,
    TakeoverNotFound,
    TakeoverScope,
    TakeoverScopeMismatch,
    TakeoverSecurityError,
    ViewerBinding,
)


SCOPE = TakeoverScope(
    principal_id="principal-a",
    profile_id="profile-a",
    hermes_session_id="hermes-session-a",
    browser_profile_id="browser-profile-a",
    browser_session_id="browser-session-a",
    transport_family="api_server",
)


class RecordingAdapter(BrowserViewerAdapter):
    adapter_id = "local-novnc"

    def __init__(self, *, dedicated=True, host="127.0.0.1"):
        self.dedicated = dedicated
        self.host = host
        self.revoked = []
        self.observe_calls = 0
        self.coordinator = None
        self.lease_id = None
        self.revoke_entered: threading.Event | None = None
        self.allow_revoke: threading.Event | None = None
        self.acquire_entered: threading.Event | None = None
        self.allow_acquire: threading.Event | None = None

    def acquire(self, scope):
        if self.acquire_entered is not None:
            self.acquire_entered.set()
        if self.allow_acquire is not None:
            assert self.allow_acquire.wait(2)
        return ViewerBinding(
            adapter_id=self.adapter_id,
            viewer_session_id="viewer-a",
            display_id=":91",
            dedicated_display=self.dedicated,
            cdp_endpoint=f"http://{self.host}:9222",
            vnc_endpoint=f"vnc://{self.host}:5901",
            novnc_endpoint=f"http://{self.host}:6081/vnc.html",
            initial_observation=BrowserObservation(
                state="still_blocked",
                active_tab_id="tab-a",
                storage_fingerprint="storage-digest-a",
            ),
        )

    def revoke(self, binding):
        self.revoked.append(binding.viewer_session_id)
        if self.revoke_entered is not None:
            self.revoke_entered.set()
        if self.allow_revoke is not None:
            assert self.allow_revoke.wait(2)

    def observe(self, binding):
        assert self.revoked == [binding.viewer_session_id]
        if self.coordinator is not None:
            blocked = self.coordinator.guard_browser_action(
                principal_id=SCOPE.principal_id,
                profile_id=SCOPE.profile_id,
                hermes_session_id=SCOPE.hermes_session_id,
                browser_profile_id=SCOPE.browser_profile_id,
                browser_session_id=SCOPE.browser_session_id,
                transport_family=SCOPE.transport_family,
            )
            assert blocked["error"]["code"] == "human_control_active"
            assert blocked["ownership"] == "returning"
        self.observe_calls += 1
        return BrowserObservation(
            state="still_blocked",
            active_tab_id="tab-a",
            storage_fingerprint="storage-digest-a",
        )


def test_lease_is_exact_scoped_and_hides_viewer_endpoints():
    coordinator = BrowserTakeoverCoordinator()
    adapter = RecordingAdapter()

    grant = coordinator.acquire(SCOPE, adapter, ttl_seconds=60)

    assert grant.scope == SCOPE
    assert grant.ownership == "human"
    rendered = repr(grant)
    assert "9222" not in rendered
    assert "5901" not in rendered
    assert "6081" not in rendered
    blocked = coordinator.guard_browser_action(
        principal_id=SCOPE.principal_id,
        profile_id=SCOPE.profile_id,
        hermes_session_id=SCOPE.hermes_session_id,
        browser_profile_id=SCOPE.browser_profile_id,
        browser_session_id=SCOPE.browser_session_id,
        transport_family=SCOPE.transport_family,
    )
    assert blocked == {
        "ok": False,
        "error": {
            "code": "human_control_active",
            "message": "Browser input is disabled while human control is active.",
        },
        "lease_id": grant.lease_id,
        "ownership": "human",
        "expires_at": grant.expires_at,
    }


def test_partial_scope_cannot_complete_or_release_agent_input():
    coordinator = BrowserTakeoverCoordinator()
    adapter = RecordingAdapter()
    grant = coordinator.acquire(SCOPE, adapter)

    with pytest.raises(TakeoverScopeMismatch):
        coordinator.complete(
            grant.lease_id,
            replace(SCOPE, profile_id="profile-b"),
        )

    assert adapter.revoked == []
    assert (
        coordinator.guard_browser_action(
            hermes_session_id=SCOPE.hermes_session_id,
            browser_session_id=SCOPE.browser_session_id,
        )["error"]["code"]
        == "human_control_active"
    )


def test_cross_profile_guard_blocks_without_disclosing_lease_metadata():
    coordinator = BrowserTakeoverCoordinator(clock=lambda: 100.0)
    coordinator.acquire(SCOPE, RecordingAdapter(), ttl_seconds=60)

    blocked = coordinator.guard_browser_action(
        principal_id=SCOPE.principal_id,
        profile_id="other-profile",
        hermes_session_id=SCOPE.hermes_session_id,
        browser_profile_id=SCOPE.browser_profile_id,
        browser_session_id=SCOPE.browser_session_id,
        transport_family=SCOPE.transport_family,
    )

    assert blocked == {
        "ok": False,
        "error": {
            "code": "human_control_active",
            "message": "Browser input is disabled while human control is active.",
        },
    }


def test_completion_revokes_before_observation_and_preserves_continuity():
    coordinator = BrowserTakeoverCoordinator()
    adapter = RecordingAdapter()
    adapter.coordinator = coordinator
    grant = coordinator.acquire(SCOPE, adapter)

    report = coordinator.complete(grant.lease_id, SCOPE)

    assert report.outcome == "still_blocked"
    assert report.continuity_verified is True
    assert report.active_tab_id == "tab-a"
    assert adapter.observe_calls == 1
    assert (
        coordinator.guard_browser_action(
            hermes_session_id=SCOPE.hermes_session_id,
            browser_session_id=SCOPE.browser_session_id,
        )
        is None
    )


def test_acquire_rejects_shared_display_or_non_loopback_listener():
    class WrongPathAdapter(RecordingAdapter):
        def acquire(self, scope):
            return replace(
                super().acquire(scope),
                novnc_endpoint="http://127.0.0.1:6081/admin",
            )

    for adapter in (
        RecordingAdapter(dedicated=False),
        RecordingAdapter(host="localhost"),
        RecordingAdapter(host="192.0.2.10"),
        WrongPathAdapter(),
    ):
        coordinator = BrowserTakeoverCoordinator()
        with pytest.raises(TakeoverSecurityError):
            coordinator.acquire(SCOPE, adapter)
        assert adapter.revoked == ["viewer-a"]


def test_expiry_revokes_before_browser_actions_resume():
    now = [100.0]
    coordinator = BrowserTakeoverCoordinator(clock=lambda: now[0])
    adapter = RecordingAdapter()
    grant = coordinator.acquire(SCOPE, adapter, ttl_seconds=60)
    now[0] = 161.0

    assert (
        coordinator.guard_browser_action(
            principal_id=SCOPE.principal_id,
            profile_id=SCOPE.profile_id,
            hermes_session_id=SCOPE.hermes_session_id,
            browser_profile_id=SCOPE.browser_profile_id,
            browser_session_id=SCOPE.browser_session_id,
            transport_family=SCOPE.transport_family,
        )
        is None
    )
    assert adapter.revoked == ["viewer-a"]
    with pytest.raises(TakeoverExpired):
        coordinator.complete(grant.lease_id, SCOPE)


def test_concurrent_completion_revokes_only_once_and_is_idempotent():
    coordinator = BrowserTakeoverCoordinator(clock=lambda: 100.0)
    adapter = RecordingAdapter()
    adapter.revoke_entered = threading.Event()
    adapter.allow_revoke = threading.Event()
    grant = coordinator.acquire(SCOPE, adapter, ttl_seconds=60)
    reports = []
    errors = []

    def finish():
        try:
            reports.append(coordinator.complete(grant.lease_id, SCOPE))
        except Exception as exc:  # test captures any race failure
            errors.append(exc)

    first = threading.Thread(target=finish)
    second = threading.Thread(target=finish)
    first.start()
    assert adapter.revoke_entered.wait(2)
    second.start()
    adapter.allow_revoke.set()
    first.join(2)
    second.join(2)

    assert errors == []
    assert len(reports) == 2
    assert reports[0] == reports[1]
    assert adapter.revoked == ["viewer-a"]


def test_only_one_takeover_can_own_a_browser_session():
    coordinator = BrowserTakeoverCoordinator()
    coordinator.acquire(SCOPE, RecordingAdapter())

    with pytest.raises(TakeoverConflict):
        coordinator.acquire(
            replace(SCOPE, hermes_session_id="other-hermes-session"),
            RecordingAdapter(),
        )


def test_reset_racing_acquire_revokes_late_viewer_and_never_publishes_human():
    coordinator = BrowserTakeoverCoordinator()
    adapter = RecordingAdapter()
    adapter.acquire_entered = threading.Event()
    adapter.allow_acquire = threading.Event()
    errors = []

    def start():
        try:
            coordinator.acquire(SCOPE, adapter)
        except Exception as exc:  # expected cancellation is asserted below
            errors.append(exc)

    thread = threading.Thread(target=start)
    thread.start()
    assert adapter.acquire_entered.wait(2)
    coordinator.reset()
    adapter.allow_acquire.set()
    thread.join(2)

    assert errors and isinstance(errors[0], TakeoverConflict)
    assert adapter.revoked == ["viewer-a"]
    assert (
        coordinator.guard_browser_action(
            hermes_session_id=SCOPE.hermes_session_id,
            browser_session_id=SCOPE.browser_session_id,
        )
        is None
    )


def test_terminal_lease_history_is_bounded():
    coordinator = BrowserTakeoverCoordinator(max_terminal_leases=2)
    grants = []
    for index in range(3):
        scope = replace(
            SCOPE,
            browser_session_id=f"browser-session-{index}",
            hermes_session_id=f"hermes-session-{index}",
        )
        grant = coordinator.acquire(scope, RecordingAdapter())
        coordinator.complete(grant.lease_id, scope)
        grants.append((grant, scope))

    assert coordinator.lease_count == 2
    with pytest.raises(TakeoverNotFound):
        coordinator.complete(grants[0][0].lease_id, grants[0][1])
