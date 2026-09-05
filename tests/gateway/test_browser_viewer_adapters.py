"""Contract tests for the local loopback noVNC viewer adapter."""

import pytest

from gateway.browser_takeover import BrowserObservation, TakeoverScope
from gateway.browser_viewer_adapters import (
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
        novnc_endpoint="http://127.0.0.1:16080/vnc.html",
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
