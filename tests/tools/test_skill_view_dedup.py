"""Behavior contracts for session-scoped projection-aware skill_view dedup."""

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest

import tools.skills_tool as skills_tool
from tools.skills_tool import _skill_view_with_bump, reset_skill_view_dedup


@pytest.fixture
def skills_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    skills = home / "skills"
    demo = skills / "demo-dedup-skill"
    demo.mkdir(parents=True)
    (demo / "SKILL.md").write_text(
        "---\nname: demo-dedup-skill\ndescription: Demo skill.\n---\n"
        "# Demo\n\n## Alpha\nAlpha procedure.\n\n## Beta\nBeta procedure.\n"
    )
    refs = demo / "references"
    refs.mkdir()
    (refs / "guide.md").write_text("# Guide\n\nDetailed reference content.\n")

    router = skills / "router"
    router.mkdir()
    (router / "SKILL.md").write_text(
        "---\nname: router\nmetadata:\n  hermes:\n    composition:\n"
        "      type: router\n      children:\n        - id: child\n"
        "          skill: child\n          trigger: Initial trigger\n---\n# Router\n"
    )
    child = skills / "child"
    child.mkdir()
    (child / "SKILL.md").write_text(
        "---\nname: child\nmetadata:\n  hermes:\n    composition:\n"
        "      type: procedure\n---\n# Child\nPrivate body.\n"
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    reset_skill_view_dedup()
    return home


def _view(
    name="demo-dedup-skill",
    *,
    task="task-a",
    session=None,
    **projection,
):
    args = {"name": name, **projection}
    return json.loads(
        _skill_view_with_bump(args, task_id=task, session_id=session)
    )


def _is_hash(value):
    return isinstance(value, str) and len(value) == 64 and all(
        char in "0123456789abcdef" for char in value
    )


class TestSkillViewDedup:
    def test_first_full_view_has_stable_public_hashes_and_repeat_is_stub(self, skills_home):
        first = _view()
        second = _view()
        assert "Alpha procedure" in first["content"]
        assert _is_hash(first["retrieval_id"])
        assert _is_hash(first["content_hash"])
        assert "_source_path" not in first
        assert second["dedup"] is True
        assert second["content_returned"] is False
        assert second["retrieval_id"] == first["retrieval_id"]
        assert second["content_hash"] == first["content_hash"]
        assert "content" not in second

    def test_projection_repeat_dedups_but_different_heading_does_not(self, skills_home):
        alpha = _view(heading="Alpha")
        alpha_again = _view(heading="Alpha")
        beta = _view(heading="Beta")
        assert alpha_again["dedup"] is True
        assert "Beta procedure" in beta["content"]
        assert beta.get("dedup") is not True
        assert alpha["retrieval_id"] != beta["retrieval_id"]

    def test_omitted_and_explicit_default_projection_budget_are_equivalent(self, skills_home):
        first = _view(heading="Alpha")
        second = _view(heading="Alpha", max_chars=8000)
        assert second["dedup"] is True
        assert second["retrieval_id"] == first["retrieval_id"]

    def test_router_implicit_and_explicit_default_budget_are_equivalent(self, skills_home):
        first = _view("router")
        second = _view("router", max_chars=8000)
        assert second["dedup"] is True
        assert second["retrieval_id"] == first["retrieval_id"]

    def test_children_none_and_empty_are_distinct(self, skills_home):
        inventory = _view("router", children=None)
        none_selected = _view("router", children=[])
        assert inventory["retrieval_id"] != none_selected["retrieval_id"]
        assert "child: Initial trigger" in inventory["content"]
        assert none_selected["content"] == ""

    def test_children_order_and_duplicates_are_canonical(self, skills_home):
        first = _view("router", children=["child", "child"])
        second = _view("router", children=["child"])
        assert second["dedup"] is True
        assert first["retrieval_id"] == second["retrieval_id"]

    def test_session_scope_precedes_task_and_is_isolated(self, skills_home):
        first = _view(task="task-a", session="session-one")
        shared = _view(task="task-b", session="session-one")
        isolated = _view(task="task-a", session="session-two")
        assert shared["dedup"] is True
        assert isolated.get("dedup") is not True
        assert first["retrieval_id"] == isolated["retrieval_id"]

    def test_task_scope_is_fallback_and_no_scope_never_dedups(self, skills_home):
        _view(task="task-a")
        assert _view(task="task-a")["dedup"] is True
        assert _view(task="task-b").get("dedup") is not True
        first = _view(task=None)
        second = _view(task=None)
        assert first.get("dedup") is not True
        assert second.get("dedup") is not True
        assert "content_hash" in first

    def test_mtime_only_change_still_dedups(self, skills_home):
        first = _view()
        path = skills_home / "skills" / "demo-dedup-skill" / "SKILL.md"
        stat = path.stat()
        os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))
        second = _view()
        assert second["dedup"] is True
        assert second["content_hash"] == first["content_hash"]

    def test_same_size_same_mtime_content_change_returns_full(self, skills_home):
        _view()
        path = skills_home / "skills" / "demo-dedup-skill" / "SKILL.md"
        original = path.read_text()
        stat = path.stat()
        changed = original.replace("Alpha procedure", "Omega procedure")
        assert len(changed) == len(original)
        path.write_text(changed)
        os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        second = _view()
        assert second.get("dedup") is not True
        assert "Omega procedure" in second["content"]

    def test_router_child_metadata_change_invalidates_root(self, skills_home):
        first = _view("router")
        child = skills_home / "skills" / "child" / "SKILL.md"
        child.write_text(child.read_text().replace("type: procedure", "type: procedure\n      content_chars: 777"))
        second = _view("router")
        assert second.get("dedup") is not True
        assert second["content_hash"] != first["content_hash"]
        assert second["composition"]["cost"]["direct_child_chars"] == 777

    def test_setup_needed_and_failures_never_record(self, monkeypatch):
        setup = json.dumps(
            {
                "success": True,
                "name": "x",
                "setup_needed": True,
                "_source_path": "/private/setup/path",
            }
        )
        failure = json.dumps({"success": False, "name": "x", "error": "bad"})
        with (
            patch.object(skills_tool, "skill_view", return_value=setup),
            patch("tools.skill_usage.bump_view") as bump_view,
            patch("tools.skill_usage.bump_use") as bump_use,
        ):
            first = _view("x")
            second = _view("x")
            assert first == second
            assert _is_hash(first["retrieval_id"])
            assert _is_hash(first["content_hash"])
            assert "_source_path" not in first
            assert first.get("dedup") is not True
            bump_view.assert_not_called()
            bump_use.assert_not_called()
        with patch.object(skills_tool, "skill_view", return_value=failure):
            assert _view("x") == json.loads(failure)
            assert _view("x") == json.loads(failure)

    def test_identity_failure_returns_sanitized_explicit_failure(self, monkeypatch):
        payload = json.dumps(
            {"success": True, "name": "x", "_source_path": "/private/path"}
        )
        with (
            patch.object(skills_tool, "skill_view", return_value=payload),
            patch.object(
                skills_tool,
                "_skill_view_identity",
                side_effect=TypeError("not serializable"),
            ),
        ):
            result = _view("x")
        assert result == {
            "success": False,
            "error_code": "skill_view_identity_failed",
            "error": "Could not compute a safe skill content identity",
            "name": "x",
        }

    def test_source_identity_distinguishes_same_visible_name(self):
        args = {"name": "same"}
        first = {"success": True, "name": "same", "_source_path": "/one/SKILL.md"}
        second = {"success": True, "name": "same", "_source_path": "/two/SKILL.md"}
        first_id, _, first_projection = skills_tool._skill_view_identity(args, first)
        second_id, _, second_projection = skills_tool._skill_view_identity(args, second)
        assert first_id != second_id
        assert first_projection["source_identity"] != second_projection["source_identity"]
        assert "/one/" not in json.dumps(first_projection)

    def test_task_reset_clears_every_associated_session(self, skills_home):
        _view(task="task-a", session="shared")
        assert _view(task="task-b", session="shared")["dedup"] is True
        reset_skill_view_dedup("task-b")
        assert _view(task="task-a", session="shared").get("dedup") is not True

    def test_reset_all_and_compression_hook_seam(self, skills_home):
        _view()
        reset_skill_view_dedup()
        assert _view().get("dedup") is not True
        from tools.skills_tool import reset_skill_view_dedup as hook
        hook("task-a")

    def test_entry_and_alias_caps_are_fifo(self, skills_home, monkeypatch):
        monkeypatch.setattr(skills_tool, "_SKILL_VIEW_DEDUP_CAP", 2)
        monkeypatch.setattr(skills_tool, "_SKILL_VIEW_SCOPE_ALIAS_CAP", 2)
        _view(heading="Alpha", task="one", session="s-one")
        _view(heading="Beta", task="two", session="s-two")
        _view(query="procedure", task="three", session="s-three")
        assert "session:s-one" not in skills_tool._skill_view_tracker
        assert len(skills_tool._skill_view_tracker["session:s-three"]) == 1
        assert list(skills_tool._skill_view_scope_tasks) == ["two", "three"]

    def test_concurrent_identical_calls_atomically_return_one_full_one_stub(self, skills_home):
        reset_skill_view_dedup()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: _view(session="concurrent"), range(2)))
        assert sum(result.get("dedup") is True for result in results) == 1
        assert sum("content" in result for result in results) == 1
        assert {result["content_hash"] for result in results} == {
            results[0]["content_hash"]
        }

    def test_linked_file_identity_is_independent(self, skills_home):
        _view()
        first = _view(file_path="references/guide.md")
        second = _view(file_path="references/guide.md")
        assert "Detailed reference" in first["content"]
        assert second["dedup"] is True
