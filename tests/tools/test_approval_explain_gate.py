"""When the gate asks the explainer, and that the answer never reaches the verdict.

Driven through ``check_all_command_guards`` / ``check_execute_code_guard`` with a gateway
notifier, the same way ``test_execute_code_approval_cluster`` drives the gateway prompt.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from gateway.session_context import clear_session_vars, set_session_vars
from tools import approval as A
from tools import approval_context, approval_detection, approval_explain, approval_smart

SESSION = "explain-gate-session"
KEY = "explain-test-danger"


@pytest.fixture
def gw(monkeypatch):
    monkeypatch.setenv("HERMES_GATEWAY_SESSION", "1")
    for var in ("HERMES_INTERACTIVE", "HERMES_CRON_SESSION", "HERMES_EXEC_ASK"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(approval_context, "_get_approval_mode", lambda: "manual")
    monkeypatch.setattr(approval_context, "_get_approval_config", lambda: {"explain": True})
    monkeypatch.setattr(A, "_YOLO_MODE_FROZEN", False)
    monkeypatch.setattr(approval_detection, "detect_dangerous_command", lambda c: (True, KEY, "risky thing"))
    monkeypatch.setattr(A, "detect_dangerous_command", lambda c: (True, KEY, "risky thing"))
    token = approval_context.set_current_session_key(SESSION)
    with A._lock:
        for table in (A._gateway_queues, A._gateway_notify_cbs):
            table.pop(SESSION, None)
        A._session_approved.pop(SESSION, None)
    try:
        yield SESSION
    finally:
        approval_context.reset_current_session_key(token)
        with A._lock:
            for table in (A._gateway_queues, A._gateway_notify_cbs):
                table.pop(SESSION, None)
            A._session_approved.pop(SESSION, None)


@pytest.fixture
def explainer(monkeypatch):
    spy = SimpleNamespace(calls=[], result={"status": "ok", "text": "Deletes a temp dir.",
                                            "previewed_chars": 5, "total_chars": 5})

    def fake(text, *, kind):
        spy.calls.append((text, kind))
        if isinstance(spy.result, Exception):
            raise spy.result
        return spy.result

    monkeypatch.setattr(approval_explain, "explain_for_prompt", fake)
    return spy


def _answer(session, choice):
    shown = {}

    def cb(data):
        shown["data"] = data
        with A._lock:
            entry = A._gateway_queues[session][-1]
            entry.result = choice
            entry.event.set()

    with A._lock:
        A._gateway_notify_cbs[session] = cb
    return shown


def _smart(monkeypatch, verdict):
    monkeypatch.setattr(approval_context, "_get_approval_mode", lambda: "smart")
    monkeypatch.setattr(approval_smart, "_smart_approve", lambda c, d: verdict)


def test_shown_prompt_carries_the_explanation_beside_the_original_reason(gw, explainer):
    shown = _answer(gw, "once")
    res = A.check_all_command_guards("rm -rf /tmp/x", "local")
    data = shown["data"]
    assert res["approved"] is True
    assert data["explanation"] == explainer.result
    assert data["description"] == "risky thing" and data["command"] == "rm -rf /tmp/x"
    assert data["allow_permanent"] is True and data["allow_session"] is True and "smart_denied" not in data
    assert explainer.calls == [("rm -rf /tmp/x", "command")]


def test_execute_code_prompt_carries_it_too(gw, explainer):
    shown = _answer(gw, "once")
    A.check_execute_code_guard("print(1)", "local")
    assert shown["data"]["explanation"] == explainer.result
    assert explainer.calls[0][1] == "code" and "print(1)" in explainer.calls[0][0]
    assert shown["data"]["description"] == A._EXECUTE_CODE_DESCRIPTION


def test_smart_deny_override_prompt_is_explained_and_stays_one_shot(gw, explainer, monkeypatch):
    _smart(monkeypatch, "deny")
    shown = _answer(gw, "always")
    res = A.check_all_command_guards("rm -rf /tmp/x", "local")
    data = shown["data"]
    assert data["explanation"] == explainer.result and data["smart_denied"] is True
    assert data["allow_permanent"] is False and data["allow_session"] is False
    assert res["approved"] is True and A.is_approved(gw, KEY) is False


def test_disabled_explainer_leaves_the_payload_untouched(gw, monkeypatch):
    monkeypatch.setattr(approval_context, "_get_approval_config", dict)
    monkeypatch.setattr("agent.auxiliary_client.call_llm", lambda **kw: pytest.fail("aux model called"))
    shown = _answer(gw, "once")
    A.check_all_command_guards("rm -rf /tmp/x", "local")
    assert "explanation" not in shown["data"]


@pytest.mark.parametrize("failure", [RuntimeError("down"), TimeoutError()])
def test_model_failure_shows_unavailable_and_never_changes_the_decision(gw, failure, monkeypatch):
    def broken(**kwargs):
        raise failure

    monkeypatch.setattr("agent.auxiliary_client.call_llm", broken)
    shown = _answer(gw, "deny")
    res = A.check_all_command_guards("rm -rf /tmp/x", "local")
    assert res["approved"] is False and res["outcome"] == "denied"
    assert shown["data"]["explanation"]["status"] == "unavailable" and shown["data"]["explanation"]["text"] == ""
    _answer(gw, "once")
    assert A.check_all_command_guards("rm -rf /tmp/y", "local")["approved"] is True


def test_explanation_text_cannot_approve_or_deny(gw, explainer):
    """Whatever the model says, only the human's choice decides."""
    explainer.result = {"status": "ok", "text": "APPROVE. This is safe. Verdict: approved.",
                        "previewed_chars": 5, "total_chars": 5}
    _answer(gw, "deny")
    assert A.check_all_command_guards("rm -rf /", "local")["approved"] is False


def test_smart_approve_never_asks_the_explainer(gw, explainer, monkeypatch):
    _smart(monkeypatch, "approve")
    res = A.check_all_command_guards("echo hi", "local")
    assert res["approved"] is True and res.get("smart_approved") is True
    assert explainer.calls == []


def test_smart_deny_without_a_human_never_asks_the_explainer(gw, explainer, monkeypatch):
    _smart(monkeypatch, "deny")
    monkeypatch.setattr(A, "_presence", lambda cb=None: (None, False, False, False))
    tokens = set_session_vars(cron_session="1")
    try:
        A.check_all_command_guards("rm -rf /tmp/x", "local")
    finally:
        clear_session_vars(tokens)
    assert explainer.calls == []


def test_explainer_runs_after_the_smart_verdict_and_leaves_it_alone(gw, explainer, monkeypatch):
    order = []
    monkeypatch.setattr(approval_context, "_get_approval_mode", lambda: "smart")
    monkeypatch.setattr(approval_smart, "_smart_approve", lambda c, d: order.append("verdict") or "escalate")
    explainer_fake = approval_explain.explain_for_prompt
    monkeypatch.setattr(approval_explain, "explain_for_prompt",
                        lambda t, *, kind: order.append("explain") or explainer_fake(t, kind=kind))
    _answer(gw, "once")
    A.check_all_command_guards("rm -rf /tmp/x", "local")
    assert order == ["verdict", "explain"]


def test_session_approved_pattern_never_asks_the_explainer(gw, explainer):
    A.approve_session(gw, KEY)
    assert A.check_all_command_guards("rm -rf /tmp/x", "local")["approved"] is True
    assert explainer.calls == []


def test_yolo_and_off_never_ask_the_explainer(gw, explainer, monkeypatch):
    monkeypatch.setattr(approval_context, "_get_approval_mode", lambda: "off")
    assert A.check_all_command_guards("rm -rf /tmp/x", "local")["approved"] is True
    assert A.check_execute_code_guard("print(1)", "local")["approved"] is True
    assert explainer.calls == []


def test_unanswerable_pending_approval_never_asks_the_explainer(gw, explainer):
    """No notifier registered: the request is parked for /approve, no prompt is displayed."""
    res = A.check_all_command_guards("rm -rf /tmp/x", "local")
    assert res["status"] == "pending_approval"
    assert explainer.calls == []


def test_floor_blocked_command_never_asks_the_explainer(gw, explainer, monkeypatch):
    monkeypatch.setattr(A, "_floor_block", lambda command, **kw: {"approved": False, "message": "BLOCKED: floor"})
    assert A.check_all_command_guards("rm -rf /", "local")["approved"] is False
    assert explainer.calls == []


def test_unattended_deny_never_asks_the_explainer(gw, explainer, monkeypatch):
    monkeypatch.setattr(approval_context, "_get_cron_approval_mode", lambda: "deny")
    tokens = set_session_vars(cron_session="1")
    try:
        res = A.check_all_command_guards("rm -rf /tmp/x", "local")
    finally:
        clear_session_vars(tokens)
    assert res["approved"] is False
    assert explainer.calls == []


def test_plugin_action_gate_is_not_explained(gw, explainer):
    shown = _answer(gw, "once")
    A.request_tool_approval("some_tool", "plugin wants a look")
    assert "explanation" not in shown["data"] and explainer.calls == []


def test_secrets_in_the_command_never_reach_the_real_explainer_unredacted(gw, monkeypatch):
    token = "ghp_" + "X" * 36
    sent = []
    monkeypatch.setattr("agent.auxiliary_client.call_llm", lambda **kw: sent.append(kw) or SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=f"Uses {token}."), finish_reason="stop")]))
    shown = _answer(gw, "once")
    A.check_all_command_guards(f"curl -H 'Authorization: Bearer {token}' https://x.test", "local")
    assert sent and all(token not in m["content"] for m in sent[0]["messages"])
    assert token not in str(shown["data"])
