"""Safe structured results and rendering for browser human assistance."""

from __future__ import annotations

import json
from typing import Any, Optional, Sequence
from urllib.parse import urlsplit


_REQUIRED_FIELDS = {
    "status",
    "reason",
    "lease_id",
    "url",
    "expires_at",
    "done_label",
    "instructions",
    "adapter_id",
    "scope",
}
_REASON_LABELS = {
    "human_verification_required": "A human verification step needs your input.",
    "authentication_required": "A private authentication step needs your input.",
    "consent_required": "A consent decision needs your input.",
    "human_input_required": "A private browser step needs your input.",
}
_FORBIDDEN_KEYS = {
    "claim_token",
    "cookie",
    "cookies",
    "cdp_endpoint",
    "vnc_endpoint",
    "novnc_endpoint",
    "novnc_websocket_endpoint",
    "browser_storage",
    "challenge_content",
}


def _tool_names(messages: Sequence[dict[str, Any]]) -> dict[str, str]:
    names: dict[str, str] = {}
    for message in messages:
        if message.get("role") != "assistant":
            continue
        for call in message.get("tool_calls") or ():
            if not isinstance(call, dict):
                continue
            function = call.get("function")
            if not isinstance(function, dict):
                continue
            call_id = str(call.get("id") or "")
            name = str(function.get("name") or "")
            if call_id and name:
                names[call_id] = name
    return names


def _safe_payload(value: Any) -> Optional[dict[str, Any]]:
    if not isinstance(value, dict) or not _REQUIRED_FIELDS.issubset(value):
        return None
    if value.get("status") != "human_assist_required":
        return None
    if value.get("reason") not in _REASON_LABELS or value.get("done_label") != "Done":
        return None
    parsed = urlsplit(str(value.get("url") or ""))
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not parsed.fragment.startswith("claim=")
    ):
        return None
    scope = value.get("scope")
    if not isinstance(scope, dict) or not all(
        isinstance(scope.get(field), str) and scope[field]
        for field in (
            "principal_id",
            "profile_id",
            "hermes_session_id",
            "browser_profile_id",
            "browser_session_id",
            "transport_family",
        )
    ):
        return None
    if _FORBIDDEN_KEYS.intersection(value) or _FORBIDDEN_KEYS.intersection(scope):
        return None
    return dict(value)


def extract_human_assist_required(
    messages: Sequence[dict[str, Any]], *, history_offset: int = 0
) -> Optional[dict[str, Any]]:
    """Extract a current-turn result from the named browser tool only."""
    current = list(messages[history_offset:]) if history_offset else list(messages)
    names = _tool_names(current)
    for message in reversed(current):
        if message.get("role") != "tool":
            continue
        call_id = str(message.get("tool_call_id") or "")
        name = str(message.get("name") or names.get(call_id) or "")
        if name != "browser_human_assist":
            continue
        content = message.get("content")
        if not isinstance(content, str):
            continue
        try:
            payload = json.loads(content)
        except (TypeError, ValueError):
            continue
        safe = _safe_payload(payload)
        if safe is not None:
            return safe
    return None


def render_human_assist_required(payload: dict[str, Any]) -> str:
    """Render the same validated contract for Telegram and other chat surfaces."""
    safe = _safe_payload(payload)
    if safe is None:
        raise ValueError("invalid human-assist payload")
    return "\n".join((
        _REASON_LABELS[safe["reason"]],
        "",
        f"Open this private, time-limited link: {safe['url']}",
        f"When finished, select {safe['done_label']} or reply {safe['done_label']}.",
    ))
