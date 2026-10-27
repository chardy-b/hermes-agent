"""Shared wording for the exec-approval prompt every messaging surface renders.

The button card (``BasePlatformAdapter._format_exec_approval``) and the plain-text
``/approve`` fallback (``gateway.run._format_exec_approval_fallback``) must tell the user
the same three things: what Hermes wants to run, why it was flagged, and that silence means
the command does NOT run once ``approvals.timeout`` elapses. Keeping the text here means one
edit changes every platform; adapters only wrap these strings in their own markup.

The ``EA_*`` / ``APPROVAL_TIMED_OUT_NOTICE`` module constants are the English source of truth
(catalog keys ``gateway.exec_approval.*``); anything that renders the prompt calls the sibling
accessors (``ea_header_text()`` …) so the active ``display.language`` is honoured at render time.

No imports from ``gateway.platforms.base`` or ``gateway.run`` — both import this module.
"""

from __future__ import annotations

from agent.i18n import t

# Bare strings; adapters add their own bold/HTML around them.
EA_HEADER_TEXT = "Hermes wants to run a command that needs your OK"
EA_REASON_LABEL_TEXT = "Why it was flagged"

# Timeout notice posted when nobody answered the prompt (``{window}`` = "5 minutes").
APPROVAL_TIMED_OUT_NOTICE = (
    "⌛ Approval timed out after {window} — the command was NOT run. "
    "Ask me to try again if you still want it, or raise approvals.timeout in config.yaml.")


def ea_header_text() -> str:
    """Localized ``EA_HEADER_TEXT``."""
    return t("gateway.exec_approval.header")


def ea_reason_label_text() -> str:
    """Localized ``EA_REASON_LABEL_TEXT``."""
    return t("gateway.exec_approval.reason_label")


def ea_smart_deny_line_text() -> str:
    """Localized smart-deny sentence (bare; adapters add their own line breaks/markup)."""
    return t("gateway.exec_approval.smart_deny_line")


def ea_default_reason_text() -> str:
    """Localized default "why it was flagged" reason when the approval carries none."""
    return t("gateway.exec_approval.default_reason")


def ea_action_labels() -> dict[str, str]:
    """Localized ``choice -> button label`` for the four approval tiers."""
    return {
        "once": t("gateway.exec_approval.action_once"),
        "session": t("gateway.exec_approval.action_session"),
        "always": t("gateway.exec_approval.action_always"),
        "deny": t("gateway.exec_approval.action_deny"),
    }


def approval_timed_out_notice(window: str) -> str:
    """Localized ``APPROVAL_TIMED_OUT_NOTICE`` for an already-formatted ``window``."""
    return t("gateway.exec_approval.timed_out_notice", window=window)


def approval_timeout_seconds() -> int:
    """The configured ``approvals.timeout`` (default 300s); module attribute so tests can pin it."""
    from tools.approval_context import _get_approval_timeout
    return _get_approval_timeout()


def format_approval_window(seconds: int) -> str:
    """Human wording for a timeout (300 → "5 minutes"); one formatter shared with the CLI notice and
    the tool result's ``user_summary`` — see ``tools.approval_context.format_approval_window``."""
    from tools.approval_context import format_approval_window as _shared
    return _shared(seconds)


def format_approval_deadline_line(timeout_s: int) -> str:
    """The last line of every approval prompt: doing nothing is a safe no."""
    return t("gateway.exec_approval.deadline", window=format_approval_window(timeout_s))


def format_approval_timed_out_notice(timeout_s: int) -> str:
    return approval_timed_out_notice(format_approval_window(timeout_s))


def ea_explanation_parts(explanation: dict | None) -> tuple[str, str] | None:
    """``(label, body)`` for the optional AI explanation of the flagged command, or None when the prompt
    carries none. An unavailable explanation renders as an explicit notice, and a prefix-only one says
    how much of the command the model saw. Adapters wrap these bare strings in their own markup."""
    if not explanation:
        return None
    label = t("gateway.exec_approval.explanation_label")
    if explanation.get("status") != "ok" or not explanation.get("text"):
        return label, t("gateway.exec_approval.explanation_unavailable")
    body = str(explanation["text"])
    previewed, total = explanation.get("previewed_chars", 0), explanation.get("total_chars", 0)
    if previewed < total:
        body += " " + t("gateway.exec_approval.explanation_partial", previewed=previewed, total=total)
    return label, body


def ea_explanation_text(explanation: dict | None) -> str:
    """Plain-text ``Label: body`` paragraph (blank-line terminated) for the text fallback; "" without one."""
    parts = ea_explanation_parts(explanation)
    return f"{parts[0]}: {parts[1]}\n\n" if parts else ""


def redact_explanation(explanation: dict | None) -> dict | None:
    """Copy of the payload's AI explanation with its text re-redacted for display (the explainer already
    redacted it; this is the egress-side guard, like ``gateway.run._redact_approval_command``)."""
    if not explanation:
        return None
    from agent.redact import redact_sensitive_text
    return {**explanation, "text": redact_sensitive_text(str(explanation.get("text") or ""), force=True)}


def fit_escaped(text: str, budget: int, suffix: str, escape, len_fn) -> str:
    """Longest prefix of *text* whose ``escape``d form measures ``<= budget`` in ``len_fn`` units, plus *suffix*
    when cut (the suffix rides outside the budget). Escaped length is monotonic in the raw prefix, so bisect."""
    if len_fn(escape(text)) <= budget:
        return text
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        lo, hi = (mid, hi) if len_fn(escape(text[:mid])) <= budget else (lo, mid - 1)
    return text[:lo] + suffix


def ea_explanation_block(explanation: dict | None, markup, escape, len_fn, budget: int) -> str:
    """The AI-explanation paragraph (leading blank line) between the reason and the deadline line, "" without
    one. *markup* wraps ``(label, body)`` in the platform's formatting; a positive *budget* caps the body in
    escaped ``len_fn`` units."""
    parts = ea_explanation_parts(explanation)
    if parts is None:
        return ""
    label, body = parts
    return "\n\n" + markup(label, fit_escaped(body, budget, "...", escape, len_fn) if budget else body)
