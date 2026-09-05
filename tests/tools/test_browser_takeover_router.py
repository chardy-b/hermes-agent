"""Registry routing blocks agent input during human browser ownership."""

import builtins
import json

from gateway.browser_takeover import (
    BrowserObservation,
    BrowserTakeoverCoordinator,
    BrowserViewerAdapter,
    TakeoverScope,
    ViewerBinding,
)
from gateway.session_context import clear_session_vars, set_session_vars
from tools import browser_extension_router


class RouterAdapter(BrowserViewerAdapter):
    adapter_id = "local-novnc"

    def acquire(self, scope):
        return ViewerBinding(
            adapter_id=self.adapter_id,
            viewer_session_id="viewer-router",
            browser_profile_id=scope.browser_profile_id,
            browser_session_id=scope.browser_session_id,
            transport_family=scope.transport_family,
            display_id=":92",
            dedicated_display=True,
            cdp_endpoint="http://127.0.0.1:9223",
            vnc_endpoint="vnc://127.0.0.1:5902",
            novnc_endpoint="http://127.0.0.1:6082/vnc.html",
            novnc_websocket_endpoint="ws://127.0.0.1:6082/websockify",
            initial_observation=BrowserObservation(
                state="still_blocked",
                active_tab_id="tab-router",
                storage_fingerprint="storage-router",
            ),
        )

    def revoke(self, binding):
        return None

    def observe(self, binding):
        return binding.initial_observation


def test_routed_handler_returns_structured_block_without_fallback(monkeypatch):
    coordinator = BrowserTakeoverCoordinator()
    scope = TakeoverScope(
        principal_id="principal-router",
        profile_id="profile-router",
        hermes_session_id="hermes-router",
        browser_profile_id="browser-profile-router",
        browser_session_id="browser-router",
        transport_family="api_server",
    )
    grant = coordinator.acquire(scope, RouterAdapter())
    monkeypatch.setattr(
        "gateway.browser_takeover.get_browser_takeover_coordinator",
        lambda: coordinator,
    )
    monkeypatch.setattr(
        "gateway.browser_control_broker.browser_control_enabled",
        lambda: False,
    )
    fallback_calls = []
    tokens = set_session_vars(
        session_id=scope.hermes_session_id,
        profile=scope.profile_id,
        browser_control_principal=scope.principal_id,
        browser_control_transport_family="api_server",
    )
    try:
        result = browser_extension_router.routed_browser_handler(
            "browser_navigate",
            {"url": "https://example.test"},
            fallback=lambda: fallback_calls.append(True) or "legacy",
            task_id=scope.browser_session_id,
            browser_profile_id=scope.browser_profile_id,
            transport_family=scope.transport_family,
        )
    finally:
        clear_session_vars(tokens)

    assert json.loads(result) == {
        "ok": False,
        "error": {
            "code": "human_control_active",
            "message": "Browser input is disabled while human control is active.",
        },
        "lease_id": grant.lease_id,
        "ownership": "human",
        "expires_at": grant.expires_at,
    }
    assert fallback_calls == []

    coordinator.complete(grant.lease_id, scope)
    assert (
        browser_extension_router.routed_browser_handler(
            "browser_navigate",
            {"url": "https://example.test"},
            fallback=lambda: "legacy",
            task_id=scope.browser_session_id,
            session_id=scope.hermes_session_id,
            principal_id=scope.principal_id,
            browser_profile_id=scope.browser_profile_id,
            transport_family=scope.transport_family,
        )
        == "legacy"
    )


def test_takeover_guard_runtime_failure_blocks_instead_of_falling_back(monkeypatch):
    class BrokenCoordinator:
        def guard_browser_action(self, **kwargs):
            raise RuntimeError("private failure details")

    monkeypatch.setattr(
        "gateway.browser_takeover.get_browser_takeover_coordinator",
        lambda: BrokenCoordinator(),
    )
    fallback_calls = []

    result = browser_extension_router.routed_browser_handler(
        "browser_click",
        {"ref": "@e1"},
        fallback=lambda: fallback_calls.append(True) or "unsafe",
        task_id="browser-router",
        session_id="hermes-router",
        principal_id="principal-router",
    )

    assert json.loads(result) == {
        "ok": False,
        "error": {
            "code": "takeover_state_unavailable",
            "message": "Browser ownership could not be verified; input remains disabled.",
        },
    }
    assert fallback_calls == []


def test_missing_takeover_module_blocks_instead_of_falling_back(monkeypatch):
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "gateway.browser_takeover":
            raise ImportError("simulated missing ownership guard")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    fallback_calls = []

    result = browser_extension_router.routed_browser_handler(
        "browser_click",
        {"ref": "@e1"},
        fallback=lambda: fallback_calls.append(True) or "unsafe",
        task_id="browser-router",
        session_id="hermes-router",
        principal_id="principal-router",
    )

    assert json.loads(result)["error"]["code"] == "takeover_state_unavailable"
    assert fallback_calls == []
