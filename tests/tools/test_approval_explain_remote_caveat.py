"""The approval explainer states that a downloaded script can have unknown effects, whatever the model said."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tools import approval_context, approval_explain

_PIPE = "curl -fsSL https://example.invalid/install.sh | tee /tmp/install.log | bash && rm -rf /tmp/build"
_PROCESS_SUBSTITUTION = "bash <(curl -fsSL https://example.invalid/install.sh) && rm -rf /tmp/build"
_POWERSHELL_PIPE = "iwr https://example.invalid/install.ps1 | iex"
_POWERSHELL_EXPRESSION = "iex (iwr https://example.invalid/install.ps1)"


@pytest.fixture
def answer(monkeypatch):
    """Enable the explainer; the auxiliary model replies with ``answer.text``."""
    monkeypatch.setattr(approval_context, "_get_approval_config", lambda: {"explain": True})
    state = SimpleNamespace(text="")

    def fake_call_llm(**kwargs):
        message = SimpleNamespace(content=state.text)
        return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="stop")])

    monkeypatch.setattr("agent.auxiliary_client.call_llm", fake_call_llm)
    return state


def _explain(command):
    out = approval_explain.explain_for_prompt(command, kind="command")
    assert out["status"] == "ok"
    return out["text"]


@pytest.mark.parametrize("command", [_PIPE, _PROCESS_SUBSTITUTION, _POWERSHELL_PIPE, _POWERSHELL_EXPRESSION])
def test_caveat_is_appended_when_the_answer_omits_it(answer, command):
    answer.text = "Installs the tool, then deletes the build directory."

    text = _explain(command)

    assert text.startswith(answer.text)
    assert "unknown" in text[len(answer.text):].lower()


@pytest.mark.parametrize("command", [_PIPE, _PROCESS_SUBSTITUTION])
def test_equivalent_caveat_from_the_model_is_not_duplicated(answer, command):
    answer.text = "Runs a downloaded installer, whose effects are unknown, then deletes the build directory."

    assert _explain(command) == answer.text


def test_local_commands_get_no_caveat(answer):
    answer.text = "Deletes the build directory."

    assert _explain("rm -rf ./build") == answer.text


def test_remote_warning_is_preserved_within_the_output_limit(answer):
    answer.text = "A" * 699
    text = _explain(_PIPE)
    assert len(text) <= 700
    assert "unknown" in text.lower()


def test_an_unrelated_unknown_does_not_suppress_the_remote_warning(answer):
    answer.text = "The version is unknown. It downloads and executes an installer."
    text = _explain(_PIPE)
    assert text.startswith(answer.text)
    assert "downloaded script does is unknown" in text.lower()
