"""Structured delivery and trusted reply tests for browser takeover."""

import json

import pytest

from gateway.browser_takeover import BrowserTakeoverCoordinator, TakeoverConflict
from gateway.browser_takeover_access import TakeoverAccessManager
from gateway.browser_takeover_delivery import (
    extract_human_assist_required,
    render_human_assist_required,
)
from gateway.browser_takeover_service import (
    BrowserTakeoverService,
    get_browser_takeover_service,
    install_browser_takeover_service,
)
from gateway.run import _human_assist_response, _try_complete_browser_takeover_reply
from gateway.session_context import clear_session_vars, set_session_vars
from tools import browser_camofox
from tools.browser_tool import browser_human_assist


def _configured_service(monkeypatch):
    coordinator = BrowserTakeoverCoordinator()
    access = TakeoverAccessManager(
        coordinator,
        base_url="https://takeover.example",
    )
    service = BrowserTakeoverService(
        coordinator,
        access,
        adapter_id="camofox-vnc",
    )
    cache_key = ("profile-a", "session-a")
    with browser_camofox._sessions_lock:
        browser_camofox._sessions[cache_key] = {
            "user_id": "user-secret",
            "tab_id": "tab-secret",
            "session_key": "provider-secret",
            "managed": True,
        }
    monkeypatch.setattr(browser_camofox, "get_vnc_url", lambda: "http://127.0.0.1:6080")
    monkeypatch.setattr(browser_camofox, "check_camofox_available", lambda: True)
    return coordinator, access, service, cache_key


def _issue(service, *, principal="principal-a", reason="verification"):
    return service.issue_human_assist_for_session(
        principal_id=principal,
        profile_id="profile-a",
        hermes_session_id="session-a",
        transport_family="telegram",
        reason=reason,
        ttl_seconds=60,
    )


def test_structured_result_is_safe_and_completion_uses_exact_session(monkeypatch):
    coordinator, access, service, cache_key = _configured_service(monkeypatch)
    try:
        result = _issue(service, reason="raw CAPTCHA text must not survive")
        payload = result.to_dict()
        serialized = json.dumps(payload)

        assert payload["status"] == "human_assist_required"
        assert payload["reason"] == "human_input_required"
        assert payload["done_label"] == "Done"
        assert payload["url"].startswith("https://takeover.example/")
        assert payload["scope"]["hermes_session_id"] == "session-a"
        assert "raw CAPTCHA" not in serialized
        for forbidden in (
            "http://127.0.0.1",
            "ws://127.0.0.1",
            "vnc_endpoint",
            "cookie",
            "claim_token",
            "user-secret",
            "tab-secret",
            "provider-secret",
        ):
            assert forbidden not in serialized

        assert (
            service.complete_for_session(
                principal_id="other",
                profile_id="profile-a",
                hermes_session_id="session-a",
                transport_family="telegram",
            )
            is None
        )
        report = service.complete_for_session(
            principal_id="principal-a",
            profile_id="profile-a",
            hermes_session_id="session-a",
            transport_family="telegram",
        )
        assert report is not None
        assert report.outcome == "revoked"
        assert access.inspect(result.lease_id).revoked is True
        assert (
            coordinator.active_grant_for_session(
                principal_id="principal-a",
                profile_id="profile-a",
                hermes_session_id="session-a",
                transport_family="telegram",
            )
            is None
        )
    finally:
        coordinator.reset()
        with browser_camofox._sessions_lock:
            browser_camofox._sessions.pop(cache_key, None)


def test_service_allows_only_one_active_takeover_per_outer_session(monkeypatch):
    coordinator, _, service, cache_key = _configured_service(monkeypatch)
    try:
        _issue(service)
        with pytest.raises(TakeoverConflict):
            _issue(service)
    finally:
        coordinator.reset()
        with browser_camofox._sessions_lock:
            browser_camofox._sessions.pop(cache_key, None)


def test_browser_action_uses_installed_service_and_session_context(monkeypatch):
    from tools.registry import registry

    entry = registry._tools.get("browser_human_assist")
    assert entry is not None
    assert entry.toolset == "browser"

    coordinator, access, service, cache_key = _configured_service(monkeypatch)
    install_browser_takeover_service(service)
    tokens = set_session_vars(
        platform="telegram",
        session_id="session-a",
        profile="profile-a",
        browser_control_principal="principal-a",
        browser_control_transport_family="telegram",
    )
    try:
        payload = json.loads(
            browser_human_assist(reason="verification", task_id="session-a")
        )
        assert payload["status"] == "human_assist_required"
        assert payload["reason"] == "human_verification_required"
        assert get_browser_takeover_service() is service
        replacement = BrowserTakeoverService(
            coordinator,
            access,
            adapter_id="camofox-vnc",
        )
        with pytest.raises(ValueError):
            install_browser_takeover_service(replacement)
        assert get_browser_takeover_service() is service
    finally:
        clear_session_vars(tokens)
        install_browser_takeover_service(None)
        coordinator.reset()
        with browser_camofox._sessions_lock:
            browser_camofox._sessions.pop(cache_key, None)


def test_done_reply_completes_only_the_exact_authenticated_session(monkeypatch):
    coordinator, access, service, cache_key = _configured_service(monkeypatch)
    install_browser_takeover_service(service)
    tokens = set_session_vars(
        platform="telegram",
        session_id="session-a",
        profile="profile-a",
        browser_control_principal="principal-a",
        browser_control_transport_family="telegram",
    )
    try:
        result = _issue(service)
        assert _try_complete_browser_takeover_reply("not done") is None
        response = _try_complete_browser_takeover_reply(" Done ")
        assert response is not None
        assert "verify browser state" in response
        assert "captcha" not in response.lower()
        assert access.inspect(result.lease_id).revoked is True
    finally:
        clear_session_vars(tokens)
        install_browser_takeover_service(None)
        coordinator.reset()
        with browser_camofox._sessions_lock:
            browser_camofox._sessions.pop(cache_key, None)


def test_current_turn_tool_result_drives_one_safe_renderer():
    old_payload = {"status": "human_assist_required", "url": "https://old.invalid"}
    payload = {
        "status": "human_assist_required",
        "reason": "human_verification_required",
        "lease_id": "lease-a",
        "url": "https://takeover.example/p/profile-a/v1/browser-takeover/lease-a#claim=opaque",
        "expires_at": 200.0,
        "done_label": "Done",
        "instructions": "Open the private link. When finished, select Done or reply Done.",
        "adapter_id": "camofox-vnc",
        "scope": {
            "principal_id": "principal-a",
            "profile_id": "profile-a",
            "hermes_session_id": "session-a",
            "browser_profile_id": "browser-profile-a",
            "browser_session_id": "session-a",
            "transport_family": "telegram",
        },
    }
    messages = [
        {
            "role": "tool",
            "name": "browser_human_assist",
            "content": json.dumps(old_payload),
        },
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": "call-a",
                    "type": "function",
                    "function": {"name": "browser_human_assist", "arguments": "{}"},
                }
            ],
        },
        {"role": "tool", "tool_call_id": "call-a", "content": json.dumps(payload)},
    ]

    result = extract_human_assist_required(messages, history_offset=1)
    assert result is not None
    assert result == payload
    rendered = render_human_assist_required(result)
    assert _human_assist_response(messages, history_offset=1) == rendered
    assert "https://takeover.example/" in rendered
    assert "reply Done" in rendered
    assert "camofox" not in rendered.lower()
    assert "principal-a" not in rendered
