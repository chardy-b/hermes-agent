"""Focused tests for normalized skill hierarchy metadata."""

from agent.skill_topology import normalize_skill_topology, validate_skill_topology


def test_legacy_defaults_and_valid_metadata():
    assert normalize_skill_topology({}) == {
        "skill_role": "leaf",
        "parent_skill": None,
        "child_skills": [],
        "root_eligible": False,
        "diagnostics": [],
    }
    assert normalize_skill_topology(
        {
            "skill_role": "router",
            "parent_skill": "android",
            "child_skills": ["android-cli", "agp", "android-cli"],
            "root_eligible": True,
        }
    ) == {
        "skill_role": "router",
        "parent_skill": "android",
        "child_skills": ["android-cli", "agp"],
        "root_eligible": True,
        "diagnostics": [],
    }


def test_invalid_fields_and_semantics_are_diagnostics():
    result = normalize_skill_topology(
        {
            "skill_role": "wat",
            "parent_skill": "bad name",
            "child_skills": "android-cli",
            "root_eligible": "yes",
        }
    )
    assert result["skill_role"] == "leaf"
    assert result["parent_skill"] is None
    assert result["child_skills"] == []
    assert result["root_eligible"] is False
    assert {d["code"] for d in result["diagnostics"]} >= {
        "invalid_skill_role",
        "invalid_parent_skill",
        "invalid_child_skills",
        "invalid_root_eligible",
    }

    result = normalize_skill_topology(
        {"skill_role": "root", "root_eligible": False, "child_skills": ["child"]}
    )
    assert {d["code"] for d in result["diagnostics"]} >= {"root_not_eligible"}

    result = normalize_skill_topology({"skill_role": "leaf", "child_skills": ["child"]})
    assert any(d["code"] == "leaf_has_children" for d in result["diagnostics"])


def test_invalid_index_identifier_is_diagnosed_but_retained():
    result = validate_skill_topology(
        {"bad name": normalize_skill_topology({})}
    )["skills"]
    assert "bad name" in result
    assert any(
        diagnostic["code"] == "invalid_skill_identifier"
        for diagnostic in result["bad name"]["diagnostics"]
    )


def test_reciprocal_parent_and_child_declarations_are_not_a_cycle():
    metadata = {
        "router": normalize_skill_topology(
            {"skill_role": "router", "child_skills": ["leaf"]}
        ),
        "leaf": normalize_skill_topology({"parent_skill": "router"}),
    }
    result = validate_skill_topology(metadata)["skills"]
    assert not any(d["code"] == "cycle" for d in result["router"]["diagnostics"])
    assert not any(d["code"] == "cycle" for d in result["leaf"]["diagnostics"])


def test_graph_diagnostics_are_deterministic_and_preserve_qualified_names():
    metadata = {
        "plugin:router": normalize_skill_topology(
            {
                "skill_role": "router",
                "parent_skill": "plugin:router",
                "child_skills": ["plugin:child", "missing", "plugin:child"],
            }
        ),
        "plugin:child": normalize_skill_topology({"parent_skill": "missing-parent"}),
        "cycle-a": normalize_skill_topology({"parent_skill": "cycle-b"}),
        "cycle-b": normalize_skill_topology({"parent_skill": "cycle-a"}),
    }
    first = validate_skill_topology(metadata)
    second = validate_skill_topology(metadata)
    assert first == second
    assert first["skills"]["plugin:router"]["parent_skill"] == "plugin:router"
    assert any(d["code"] == "self_reference" for d in first["skills"]["plugin:router"]["diagnostics"])
    assert any(d["code"] == "missing_child" for d in first["skills"]["plugin:router"]["diagnostics"])
    assert any(d["code"] == "missing_parent" for d in first["skills"]["plugin:child"]["diagnostics"])
    assert any(d["code"] == "cycle" for d in first["skills"]["cycle-a"]["diagnostics"])


def test_listing_keeps_malformed_hierarchy_skills_visible(tmp_path):
    from tools.skills_tool import skills_list

    def write(name, extra):
        path = tmp_path / name
        path.mkdir()
        (path / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: {name}\n{extra}---\n\nBody.\n"
        )

    write("broken-router", "skill_role: router\nchild_skills: [missing]\n")
    write("plain", "")

    from unittest.mock import patch
    import json

    with patch("tools.skills_tool.SKILLS_DIR", tmp_path):
        result = json.loads(skills_list())

    assert {skill["name"] for skill in result["skills"]} == {"broken-router", "plain"}
    broken = next(skill for skill in result["skills"] if skill["name"] == "broken-router")
    assert broken["topology"]["skill_role"] == "router"
    assert any(d["code"] == "missing_child" for d in broken["topology"]["diagnostics"])
