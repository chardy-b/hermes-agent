"""Shared contract tests for browser takeover viewer adapters."""

from dataclasses import replace

import pytest

from gateway.browser_takeover import (
    BrowserObservation,
    BrowserTakeoverCoordinator,
    TakeoverScope,
    TakeoverScopeMismatch,
)
from gateway.browser_viewer_adapters import (
    CamofoxVNCViewerAdapter,
    DedicatedBrowserViewerSession,
    LoopbackNoVNCViewerAdapter,
    ViewerSessionUnavailable,
)


SCOPE = TakeoverScope(
    principal_id="principal-local",
    profile_id="profile-local",
    hermes_session_id="hermes-local",
    browser_profile_id="browser-profile-local",
    browser_session_id="browser-local",
    transport_family="api_server",
)


def _session(scope=SCOPE, *, healthy=True):
    events = []
    session = DedicatedBrowserViewerSession(
        scope=scope,
        viewer_session_id="viewer-local",
        display_id=":91",
        cdp_endpoint="http://127.0.0.1:19222",
        vnc_endpoint="vnc://127.0.0.1:15900",
        novnc_endpoint="http://127.0.0.1:6083/vnc.html",
        novnc_websocket_endpoint="ws://127.0.0.1:6083/websockify",
        observe=lambda: BrowserObservation(
            state="still_blocked",
            active_tab_id="tab-local",
            storage_fingerprint="sha256:local",
        ),
        revoke=lambda: events.append("revoked"),
        healthy=lambda: healthy,
    )
    return session, events


def test_adapter_acquires_only_the_exact_registered_healthy_session():
    adapter = LoopbackNoVNCViewerAdapter()
    session, events = _session()
    adapter.register(session)

    binding = adapter.acquire(SCOPE)

    assert binding.viewer_session_id == "viewer-local"
    assert binding.initial_observation.active_tab_id == "tab-local"
    assert adapter.health(binding) is True
    assert adapter.observe(binding).storage_fingerprint == "sha256:local"
    adapter.revoke(binding)
    assert events == ["revoked"]


def test_adapter_rejects_cross_profile_and_unhealthy_acquire():
    adapter = LoopbackNoVNCViewerAdapter()
    unhealthy, _ = _session(healthy=False)
    adapter.register(unhealthy)

    with pytest.raises(ViewerSessionUnavailable):
        adapter.acquire(SCOPE)

    other = TakeoverScope(
        principal_id=SCOPE.principal_id,
        profile_id="other-profile",
        hermes_session_id=SCOPE.hermes_session_id,
        browser_profile_id=SCOPE.browser_profile_id,
        browser_session_id=SCOPE.browser_session_id,
        transport_family=SCOPE.transport_family,
    )
    with pytest.raises(ViewerSessionUnavailable):
        adapter.acquire(other)


def test_adapter_rejects_duplicate_scope_or_viewer_registration():
    adapter = LoopbackNoVNCViewerAdapter()
    session, _ = _session()
    adapter.register(session)

    with pytest.raises(ValueError, match="scope"):
        adapter.register(session)

    second, _ = _session(
        TakeoverScope(
            principal_id="principal-2",
            profile_id="profile-2",
            hermes_session_id="hermes-2",
            browser_profile_id="browser-profile-2",
            browser_session_id="browser-2",
            transport_family="api_server",
        )
    )
    with pytest.raises(ValueError, match="viewer session"):
        adapter.register(second)


def _contract_adapter(kind, state):
    events = []
    observation = lambda: BrowserObservation(
        state=state["outcome"],
        active_tab_id=state["tab"],
        storage_fingerprint="sha256:shared-profile",
    )
    if kind == "local":
        adapter = LoopbackNoVNCViewerAdapter()
        adapter.register(
            DedicatedBrowserViewerSession(
                scope=SCOPE,
                viewer_session_id="viewer-contract-local",
                display_id=":97",
                cdp_endpoint="http://127.0.0.1:19722",
                vnc_endpoint="vnc://127.0.0.1:15907",
                novnc_endpoint="http://127.0.0.1:6087/vnc.html",
                novnc_websocket_endpoint="ws://127.0.0.1:6087/websockify",
                observe=observation,
                revoke=lambda: events.append("revoked"),
                healthy=lambda: state["healthy"],
            )
        )
    else:
        adapter = CamofoxVNCViewerAdapter()
        adapter.register_discovered(
            scope=SCOPE,
            viewer_session_id="viewer-contract-camofox",
            discover_vnc_url=lambda: "http://localhost:6087",
            observe=observation,
            revoke=lambda: events.append("revoked"),
            healthy=lambda: state["healthy"],
        )
    return adapter, events


@pytest.mark.parametrize("kind", ["local", "camofox"])
def test_viewer_adapters_share_acquire_health_completion_and_loss_contract(kind):
    state = {"healthy": True, "outcome": "still_blocked", "tab": "tab-contract"}
    adapter, events = _contract_adapter(kind, state)
    coordinator = BrowserTakeoverCoordinator(clock=lambda: 100.0)
    grant = coordinator.acquire(SCOPE, adapter, ttl_seconds=60)

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
    state["outcome"] = "success"
    report = coordinator.complete(grant.lease_id, SCOPE)

    assert events == ["revoked"]
    assert report.outcome == "success"
    assert report.continuity_verified is True


@pytest.mark.parametrize("kind", ["local", "camofox"])
def test_viewer_adapters_report_browser_loss_without_inventing_success(kind):
    state = {"healthy": True, "outcome": "still_blocked", "tab": "tab-contract"}
    adapter, events = _contract_adapter(kind, state)
    coordinator = BrowserTakeoverCoordinator(clock=lambda: 100.0)
    grant = coordinator.acquire(SCOPE, adapter, ttl_seconds=60)
    state.update(healthy=False, outcome="browser_lost", tab="")

    report = coordinator.complete(grant.lease_id, SCOPE)

    assert events == ["revoked"]
    assert report.outcome == "browser_lost"
    assert report.continuity_verified is False


def test_camofox_register_task_reuses_managed_identity_and_health_discovery(
    monkeypatch,
):
    from tools import browser_camofox

    session_key = browser_camofox._session_cache_key("takeover-task", SCOPE.profile_id)
    with browser_camofox._sessions_lock:
        browser_camofox._sessions[session_key] = {
            "user_id": "managed-profile-user",
            "tab_id": "tab-managed",
            "session_key": "task-managed",
            "managed": True,
            "adopt_existing_tab": False,
        }
    browser_camofox._vnc_url = "http://localhost:6087"
    browser_camofox._vnc_url_checked = True
    monkeypatch.setattr(browser_camofox, "check_camofox_available", lambda: True)
    events = []
    adapter = CamofoxVNCViewerAdapter()
    try:
        browser_profile_id, browser_session_id = adapter.browser_scope_ids(
            task_id="takeover-task", profile_id=SCOPE.profile_id
        )
        task_scope = replace(
            SCOPE,
            browser_profile_id=browser_profile_id,
            browser_session_id=browser_session_id,
        )
        adapter.register_task(
            scope=task_scope,
            task_id="takeover-task",
            observe=lambda: BrowserObservation(
                state="still_blocked",
                active_tab_id="tab-managed",
                storage_fingerprint="sha256:managed-profile",
            ),
            revoke=lambda: events.append("revoked"),
        )
        binding = adapter.acquire(task_scope)

        assert binding.browser_session_id == task_scope.browser_session_id
        assert binding.cdp_endpoint is None
        assert binding.vnc_endpoint is None
        assert "6087" not in repr(binding)
        assert adapter.health(binding) is True

        with pytest.raises(ViewerSessionUnavailable, match="browser scope"):
            CamofoxVNCViewerAdapter().register_task(
                scope=SCOPE,
                task_id="takeover-task",
                observe=lambda: BrowserObservation(state="still_blocked"),
                revoke=lambda: None,
            )

        wrong_profile = TakeoverScope(
            principal_id=SCOPE.principal_id,
            profile_id="other-profile",
            hermes_session_id=SCOPE.hermes_session_id,
            browser_profile_id=SCOPE.browser_profile_id,
            browser_session_id=SCOPE.browser_session_id,
            transport_family=SCOPE.transport_family,
        )
        with pytest.raises(ViewerSessionUnavailable):
            CamofoxVNCViewerAdapter().register_task(
                scope=wrong_profile,
                task_id="takeover-task",
                observe=lambda: BrowserObservation(state="still_blocked"),
                revoke=lambda: None,
            )

        with browser_camofox._sessions_lock:
            browser_camofox._sessions[session_key]["tab_id"] = "replacement"
        assert adapter.health(binding) is False
        adapter.revoke(binding)
        assert events == ["revoked"]
    finally:
        with browser_camofox._sessions_lock:
            browser_camofox._sessions.pop(session_key, None)


def test_camofox_production_callbacks_report_only_lifecycle_and_opaque_continuity(
    monkeypatch,
):
    from tools import browser_camofox

    task_id = "takeover-task-production"
    session_key = browser_camofox._session_cache_key(task_id, SCOPE.profile_id)
    with browser_camofox._sessions_lock:
        browser_camofox._sessions[session_key] = {
            "user_id": "managed-profile-user",
            "tab_id": "private-provider-tab",
            "session_key": "task-managed",
            "managed": True,
            "adopt_existing_tab": False,
        }
    browser_camofox._vnc_url = "http://localhost:6087"
    browser_camofox._vnc_url_checked = True
    monkeypatch.setattr(browser_camofox, "check_camofox_available", lambda: True)
    adapter = CamofoxVNCViewerAdapter()
    try:
        browser_profile_id, browser_session_id = adapter.browser_scope_ids(
            task_id=task_id, profile_id=SCOPE.profile_id
        )
        assert browser_session_id == task_id
        task_scope = replace(
            SCOPE,
            browser_profile_id=browser_profile_id,
            browser_session_id=browser_session_id,
        )
        adapter.register_task(scope=task_scope, task_id=task_id)
        coordinator = BrowserTakeoverCoordinator(clock=lambda: 100.0)
        grant = coordinator.acquire(task_scope, adapter, ttl_seconds=60)

        report = coordinator.complete(grant.lease_id, task_scope)

        assert report.outcome == "revoked"
        assert report.continuity_verified is True
        assert report.active_tab_id.startswith("camofox-tab-")
        assert "private-provider-tab" not in report.active_tab_id
    finally:
        with browser_camofox._sessions_lock:
            browser_camofox._sessions.pop(session_key, None)


def test_camofox_production_observation_reports_server_loss(monkeypatch):
    from tools import browser_camofox

    task_id = "takeover-task-lost"
    session_key = browser_camofox._session_cache_key(task_id, SCOPE.profile_id)
    with browser_camofox._sessions_lock:
        browser_camofox._sessions[session_key] = {
            "user_id": "managed-profile-user",
            "tab_id": "private-provider-tab",
            "session_key": "task-managed",
            "managed": True,
            "adopt_existing_tab": False,
        }
    browser_camofox._vnc_url = "http://localhost:6087"
    browser_camofox._vnc_url_checked = True
    healthy = [True]
    monkeypatch.setattr(browser_camofox, "check_camofox_available", lambda: healthy[0])
    adapter = CamofoxVNCViewerAdapter()
    try:
        browser_profile_id, browser_session_id = adapter.browser_scope_ids(
            task_id=task_id, profile_id=SCOPE.profile_id
        )
        task_scope = replace(
            SCOPE,
            browser_profile_id=browser_profile_id,
            browser_session_id=browser_session_id,
        )
        adapter.register_task(scope=task_scope, task_id=task_id)
        coordinator = BrowserTakeoverCoordinator(clock=lambda: 100.0)
        grant = coordinator.acquire(task_scope, adapter, ttl_seconds=60)
        healthy[0] = False

        report = coordinator.complete(grant.lease_id, task_scope)

        assert report.outcome == "browser_lost"
        assert report.continuity_verified is False
        assert report.active_tab_id == ""
    finally:
        with browser_camofox._sessions_lock:
            browser_camofox._sessions.pop(session_key, None)


def test_camofox_adapter_rejects_cross_profile_and_remote_vnc_discovery():
    adapter, _ = _contract_adapter(
        "camofox",
        {"healthy": True, "outcome": "still_blocked", "tab": "tab-contract"},
    )
    other_profile = TakeoverScope(
        principal_id=SCOPE.principal_id,
        profile_id="other-profile",
        hermes_session_id=SCOPE.hermes_session_id,
        browser_profile_id=SCOPE.browser_profile_id,
        browser_session_id=SCOPE.browser_session_id,
        transport_family=SCOPE.transport_family,
    )
    with pytest.raises(ViewerSessionUnavailable):
        adapter.acquire(other_profile)

    coordinator = BrowserTakeoverCoordinator(clock=lambda: 100.0)
    grant = coordinator.acquire(SCOPE, adapter, ttl_seconds=60)
    with pytest.raises(TakeoverScopeMismatch):
        coordinator.complete(grant.lease_id, other_profile)
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

    remote = CamofoxVNCViewerAdapter()
    with pytest.raises(ViewerSessionUnavailable, match="loopback"):
        remote.register_discovered(
            scope=SCOPE,
            viewer_session_id="viewer-remote",
            discover_vnc_url=lambda: "http://remote.example:6080",
            observe=lambda: BrowserObservation(state="still_blocked"),
            revoke=lambda: None,
            healthy=lambda: True,
        )
