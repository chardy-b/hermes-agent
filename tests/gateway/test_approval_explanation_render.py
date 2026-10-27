"""Gateway rendering of the approval explanation: Telegram card, plain-text fallback, payload hop.

The explanation rides beside the detector reason, never inside it, and the card keeps its
buttons, reason, deadline line and 4096-unit cap.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import PlatformConfig
from gateway.run import _format_exec_approval_fallback
from gateway.platforms.base import utf16_len
from plugins.platforms.telegram.adapter import TelegramAdapter

FAKE_TOKEN = "ghp_" + "X" * 36
OK = {"status": "ok", "text": "Deletes the build directory & its contents.", "previewed_chars": 20, "total_chars": 20}
CUT = {**OK, "previewed_chars": 6000, "total_chars": 12345}
GONE = {"status": "unavailable", "text": "", "previewed_chars": 20, "total_chars": 20}


def _telegram():
    adapter = TelegramAdapter(PlatformConfig(enabled=True, token="t"))
    adapter._bot = AsyncMock()
    adapter._bot.send_message = AsyncMock(return_value=SimpleNamespace(message_id=7))
    adapter._app = MagicMock()
    return adapter


@pytest.fixture
def buttons(monkeypatch):
    """Real telegram button classes may be stubs here: record ``callback_data`` and return plain rows."""
    monkeypatch.setattr("plugins.platforms.telegram.adapter.InlineKeyboardButton",
                        lambda text, callback_data: callback_data.split(":")[1])
    monkeypatch.setattr("plugins.platforms.telegram.adapter.InlineKeyboardMarkup", lambda rows: rows)


async def _send(adapter, **kw):
    kw.setdefault("command", "rm -rf build")
    kw.setdefault("description", "recursive delete")
    await adapter.send_exec_approval(chat_id="1", session_key="s", **kw)
    return adapter._bot.send_message.call_args.kwargs


@pytest.mark.asyncio
async def test_telegram_card_shows_explanation_beside_reason_and_keeps_buttons(buttons):
    adapter = _telegram()
    sent = await _send(adapter, explanation=OK)
    text = sent["text"]
    assert "recursive delete" in text and "Deletes the build directory &amp; its contents." in text
    assert text.index("recursive delete") < text.index("Deletes the build") < text.index("NOT run")
    assert [c for row in sent["reply_markup"] for c in row] == ["once", "session", "always", "deny"]


@pytest.mark.asyncio
async def test_telegram_card_without_explanation_is_unchanged():
    plain = (await _send(_telegram()))["text"]
    assert "AI" not in plain and "explanation" not in plain.lower()


@pytest.mark.asyncio
async def test_telegram_unavailable_is_explicit_and_not_blank():
    text = (await _send(_telegram(), explanation=GONE))["text"]
    assert "unavailable" in text.lower() and "recursive delete" in text


@pytest.mark.asyncio
async def test_telegram_truncated_preview_is_labelled():
    text = (await _send(_telegram(), explanation=CUT))["text"]
    assert "6000" in text and "12345" in text
    assert "6000" not in (await _send(_telegram(), explanation=OK))["text"]


@pytest.mark.asyncio
@pytest.mark.parametrize("smart_denied", [False, True])
async def test_telegram_card_with_explanation_still_fits_the_cap(smart_denied):
    adapter = _telegram()
    huge = {**OK, "text": "<&>" * 230}  # near the explainer cap, worst-case HTML expansion
    sent = await _send(adapter, command="&" * 6000, description="<r>" * 1000, explanation=huge,
                       smart_denied=smart_denied)
    assert utf16_len(sent["text"]) <= adapter.MAX_MESSAGE_LENGTH
    assert sent["reply_markup"] is not None and "&lt;&amp;&gt;" in sent["text"]


@pytest.mark.asyncio
async def test_smart_deny_card_keeps_one_shot_buttons_with_an_explanation(buttons):
    sent = await _send(_telegram(), explanation=OK, smart_denied=True, allow_permanent=False, allow_session=False)
    assert [c for row in sent["reply_markup"] for c in row] == ["once", "deny"] and "Smart DENY" in sent["text"]


def test_plain_text_fallback_shows_explanation_reason_and_steps():
    text = _format_exec_approval_fallback("rm -rf build", "recursive delete", "/", explanation=OK)
    assert "recursive delete" in text and "Deletes the build directory & its contents." in text
    assert text.index("recursive delete") < text.index("Deletes the build") < text.index("/approve")
    assert "NOT run" in text


def test_plain_text_fallback_unavailable_and_truncated_labels():
    assert "unavailable" in _format_exec_approval_fallback("c", "d", "/", explanation=GONE).lower()
    cut = _format_exec_approval_fallback("c", "d", "/", explanation=CUT)
    assert "6000" in cut and "12345" in cut


def test_plain_text_fallback_without_explanation_is_unchanged():
    base = _format_exec_approval_fallback("c", "d", "/")
    assert _format_exec_approval_fallback("c", "d", "/", explanation=None) == base


@pytest.mark.parametrize("card_success", [True, False])
def test_turn_runner_threads_a_redacted_explanation_to_card_and_fallback(card_success):
    """The notify hop passes the payload's explanation to both surfaces and re-redacts it."""
    from gateway.run_turn_runner import TurnRunner

    async def exercise():
        sent, seen = [], {}

        class Adapter:
            def pause_typing_for_chat(self, chat_id):
                pass

            async def send_exec_approval(self, **kwargs):
                seen.update(kwargs)
                sent.append(kwargs["description"])
                return SimpleNamespace(success=card_success, error=None)

            async def send(self, chat_id, text, **kwargs):
                sent.append(text)
                return SimpleNamespace(success=True)

        ctx = SimpleNamespace(_status_adapter=Adapter(), _status_chat_id="c", _status_thread_metadata=None,
                              session_key="explain-render", _loop_for_step=asyncio.get_running_loop(),
                              stream_consumer_holder=[None])
        turn = TurnRunner(SimpleNamespace(), ctx)
        leaky = {**OK, "text": f"Posts {FAKE_TOKEN} somewhere."}
        approval = {"command": "curl x", "description": "d", "explanation": leaky}
        await asyncio.to_thread(turn._approval_notify_sync, approval)
        assert seen["explanation"]["text"].startswith("Posts ") and FAKE_TOKEN not in seen["explanation"]["text"]
        if not card_success:
            assert len(sent) == 2 and "Posts" in sent[1] and FAKE_TOKEN not in sent[1]
        assert approval["explanation"] is leaky  # payload not mutated

    asyncio.run(exercise())


def test_turn_runner_without_explanation_calls_the_card_exactly_as_before():
    from gateway.run_turn_runner import TurnRunner

    async def exercise():
        seen = {}

        class Adapter:
            def pause_typing_for_chat(self, chat_id):
                pass

            async def send_exec_approval(self, **kwargs):
                seen.update(kwargs)
                return SimpleNamespace(success=True, error=None)

        ctx = SimpleNamespace(_status_adapter=Adapter(), _status_chat_id="c", _status_thread_metadata=None,
                              session_key="explain-render", _loop_for_step=asyncio.get_running_loop(),
                              stream_consumer_holder=[None])
        await asyncio.to_thread(TurnRunner(SimpleNamespace(), ctx)._approval_notify_sync,
                                {"command": "ls", "description": "d"})
        assert "explanation" not in seen

    asyncio.run(exercise())
