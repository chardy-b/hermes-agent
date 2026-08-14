"""Behavioral evidence for WIL-79 progressive skill retrieval."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agent.skill_retrieval_evaluation import evaluate_retrieval_scenarios
from tools.skills_tool import skill_view


INVARIANTS = {
    "safety": "secrets=redact",
    "environment": "device=emulator",
    "lifecycle": "linear=source-of-truth",
    "verification": "evidence=required",
}


def _frontmatter(name, composition=""):
    return f"---\nname: {name}\ndescription: {name} fixture\n{composition}---\n"


def _procedure(root: Path, name: str, marker: str):
    directory = root / name
    directory.mkdir(parents=True)
    metadata = "metadata:\n  hermes:\n    composition:\n      type: procedure\n"
    (directory / "SKILL.md").write_text(
        _frontmatter(name, metadata)
        + f"# {name}\n\n{marker}\n"
        + (f"PRIVATE-{name}-BODY " * 300)
    )


def _router(root: Path, name: str, children: list[tuple[str, str]]):
    directory = root / name
    directory.mkdir(parents=True)
    child_yaml = "".join(
        f"        - id: {child}\n          skill: {child}\n          trigger: {trigger}\n"
        for child, trigger in children
    )
    metadata = (
        "metadata:\n  hermes:\n    composition:\n      type: router\n"
        "      invariants:\n"
        "        safety: [secrets=redact]\n"
        "        environment: [device=emulator]\n"
        "        lifecycle: [linear=source-of-truth]\n"
        "        verification: [evidence=required]\n"
        "      children:\n"
        + child_yaml
    )
    (directory / "SKILL.md").write_text(
        _frontmatter(name, metadata)
        + "# Router procedure\n\nROUTER-OPERATION-MARKER\n\n"
        + ("MONOLITH-CONTEXT " * 500)
    )
    scripts = directory / "scripts"
    scripts.mkdir()
    (scripts / "passive.sh").write_text("#!/bin/sh\ntouch SHOULD-NOT-EXIST\n")
    return directory


@pytest.fixture
def retrieval_skills(tmp_path):
    android = [
        ("android-ci", "Diagnose Android CI"),
        ("android-location", "Simulate named-road location and heading"),
        ("android-visual", "Capture emulator visual evidence"),
        ("android-logs", "Diagnose bounded Android logs"),
    ]
    hermes = [
        ("hermes-approvals", "Inspect command approvals"),
        ("hermes-context", "Inspect context accounting"),
    ]
    for child, trigger in android + hermes:
        _procedure(tmp_path, child, f"OPERATION-{child.upper()}")
    android_dir = _router(tmp_path, "android-router", android)
    _router(tmp_path, "hermes-router", hermes)

    flat = tmp_path / "android-flat-control"
    flat.mkdir()
    sections = []
    for child, trigger in android:
        link = "See references/ci.md\n" if child == "android-ci" else ""
        sections.append(
            f"## {trigger}\nOPERATION-{child.upper()}\n"
            + link
            + (f"PRIVATE-{child}-BODY " * 40)
        )
    refs = flat / "references"
    refs.mkdir()
    (refs / "ci.md").write_text("CI reference")
    (refs / "visual.md").write_text("Visual reference")
    (flat / "SKILL.md").write_text(
        _frontmatter("android-flat-control")
        + "## Warnings\nsecrets=redact device=emulator linear=source-of-truth evidence=required\n\n"
        + sections[0]
        + "\n\n"
        + "\n\n".join(sections[1:])
        + "\nSee references/visual.md\n"
        + "\n## Unrelated legacy appendix\n"
        + ("UNRELATED-LEGACY-CONTEXT " * 600)
    )
    return tmp_path, android_dir


def test_android_and_hermes_routers_select_metadata_without_body_leakage(retrieval_skills):
    root, android_dir = retrieval_skills
    sentinel = android_dir / "SHOULD-NOT-EXIST"
    with patch("tools.skills_tool.SKILLS_DIR", root):
        inventory = json.loads(skill_view("android-router"))
        selected = json.loads(skill_view("android-router", children=["android-location"]))
        hermes = json.loads(skill_view("hermes-router", children=["hermes-approvals"]))

    assert [c["id"] for c in inventory["composition"]["available_children"]] == [
        "android-ci", "android-location", "android-visual", "android-logs"
    ]
    assert selected["content"] == "- android-location: Simulate named-road location and heading"
    assert hermes["content"] == "- hermes-approvals: Inspect command approvals"
    serialized = json.dumps([inventory, selected, hermes])
    assert "PRIVATE-android-location-BODY" not in serialized
    assert "PRIVATE-hermes-approvals-BODY" not in serialized
    assert inventory["composition_invariants"] == {
        category: [value] for category, value in INVARIANTS.items()
    }
    assert selected["composition_invariants"] == inventory["composition_invariants"]
    assert hermes["composition_invariants"] == {
        category: [value] for category, value in INVARIANTS.items()
    }
    assert inventory["linked_files"] is None
    assert not sentinel.exists()


def test_bounded_projection_filters_links_and_evaluation_proves_cost_and_safety(retrieval_skills):
    root, _ = retrieval_skills
    with patch("tools.skills_tool.SKILLS_DIR", root):
        baseline = skill_view("android-flat-control")
        projected = skill_view(
            "android-flat-control",
            heading="Diagnose Android CI",
            max_chars=1200,
        )
        router = skill_view("android-router")
        selected = skill_view("android-router", children=["android-ci"])

    projected_payload = json.loads(projected)
    assert list(projected_payload["linked_files"]) == ["references/ci.md"]
    assert "references/visual.md" not in projected
    scenarios = [
        {
            "name": "android-ci-section",
            "baseline_payload": baseline,
            "projected_payload": projected,
            "required_markers": ["OPERATION-ANDROID-CI", "secrets=redact"],
            "forbidden_markers": ["OPERATION-ANDROID-VISUAL"],
            "invariants": INVARIANTS,
        },
        {
            "name": "android-router-inventory",
            "baseline_payload": baseline,
            "projected_payload": router,
            "required_markers": ["android-ci", "android-location"],
            "forbidden_markers": ["PRIVATE-android-ci-BODY"],
            "invariants": INVARIANTS,
        },
        {
            "name": "android-selected-child",
            "baseline_payload": baseline,
            "projected_payload": selected,
            "required_markers": ["android-ci", "Diagnose Android CI"],
            "forbidden_markers": ["PRIVATE-android-visual-BODY", "PRIVATE-android-ci-BODY"],
            "invariants": INVARIANTS,
        },
    ]
    report = evaluate_retrieval_scenarios(scenarios)
    aggregate = report["aggregate"]
    assert aggregate["savings_percent"] >= 50
    assert aggregate["total_saved_tokens"] > 0
    assert aggregate["all_correct"] is True, report["scenarios"]
    assert aggregate["all_safe"] is True
    assert aggregate["no_leakage"] is True
    assert aggregate["parent_peak_context"] < aggregate["total_parent_tokens"]


def test_slash_loader_forces_full_router_and_flat_compatibility(retrieval_skills):
    from agent.skill_commands import _load_skill_payload

    root, _ = retrieval_skills
    with (
        patch("tools.skills_tool.SKILLS_DIR", root),
        patch("agent.skill_commands.SKILLS_DIR", root, create=True),
    ):
        public_router = json.loads(skill_view("android-router"))
        loaded_router = _load_skill_payload("android-router", task_id="slash-task")
        loaded_flat = _load_skill_payload("android-flat-control", task_id="slash-task")

    assert "MONOLITH-CONTEXT" not in public_router["content"]
    assert loaded_router is not None and "MONOLITH-CONTEXT" in loaded_router[0]["content"]
    assert loaded_flat is not None and "OPERATION-ANDROID-VISUAL" in loaded_flat[0]["content"]
    assert "projection" not in loaded_router[0]
