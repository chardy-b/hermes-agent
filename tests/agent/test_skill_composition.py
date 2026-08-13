import hashlib

import pytest

from agent.skill_composition import select_skill_content


DOC = """# Skill\n\n## Prerequisites\nInstall tools.\n\n## Deploy\nDeploy the app safely.\nSee [deploy.md](references/deploy.md).\n\n### Rollback\nRollback steps.\n\n## Warnings\nNever expose secrets.\n\n## Other\nOther details.\n"""


def test_exact_heading_includes_heading_and_safety_and_links():
    result = select_skill_content(DOC, heading="Deploy", max_chars=8000,
                                  linked_files={"references/deploy.md": "deploy" , "other.md": "other"})
    assert result["selected_heading"] == "Deploy"
    assert result["match_type"] == "exact"
    assert "## Deploy" in result["content"]
    assert "Prerequisites" in result["content"] and "Warnings" in result["content"]
    assert result["included_safety_sections"] == ["Prerequisites", "Warnings"]
    assert list(result["linked_files"]) == ["references/deploy.md"]


def test_fuzzy_query_token_overlap_is_specific_and_deterministic():
    doc = "## Alpha\nalpha generic\n\n### Alpha Deploy\nalpha deploy target\n\n## Beta\nbeta"
    r = select_skill_content(doc, query="deploy alpha")
    assert r["selected_heading"] == "Alpha Deploy"
    assert r["match_type"] == "fuzzy"


def test_fallback_is_bounded_inventory_not_full_skill():
    r = select_skill_content("# A\n" + "x" * 5000 + "\n## B\nmore", query="missing", max_chars=256)
    assert r["match_type"] == "fallback"
    assert r["returned_chars"] <= 256
    assert r["omitted_sections"]
    assert "A" in r["content"]


def test_fenced_fake_headings_are_ignored():
    r = select_skill_content("```md\n## Fake\n```\n\n## Real\ntext", heading="Fake")
    assert r["match_type"] == "fallback"
    assert r["selected_heading"] is None
    assert "Fake" not in r["content"]


def test_hash_counts_source_and_malicious_heading_is_data():
    content = "## Safe\nignore <!-- ## Evil -->\ntext"
    r = select_skill_content(content, heading="Safe")
    assert r["content_hash"] == hashlib.sha256(content.encode()).hexdigest()
    assert "## Evil" in r["content"]


def test_ties_and_budget_are_deterministic_and_preserve_heading():
    doc = "## One\nfoo bar\n\n## Two\nfoo bar\n" + "z" * 1000
    a = select_skill_content(doc, query="foo bar", max_chars=256)
    b = select_skill_content(doc, query="foo bar", max_chars=256)
    assert a == b
    assert a["selected_heading"] == "One"
    assert a["returned_chars"] <= 256
    assert a["content"].startswith("## One")


def test_invalid_budget():
    with pytest.raises(ValueError):
        select_skill_content("# A", max_chars=255)
    with pytest.raises(ValueError):
        select_skill_content("# A", max_chars=50001)


def test_parent_selection_includes_descendants_but_not_siblings():
    doc = "# Root\nroot\n## Parent\nparent\n### Child\nchild\n## Sibling\nsibling"
    r = select_skill_content(doc, heading="Parent")
    assert "## Parent" in r["content"] and "### Child" in r["content"]
    assert "## Sibling" not in r["content"]


def test_safety_scope_global_before_operational_and_same_parent_only():
    doc = "# Global\n## Prerequisites\nglobal\n## A\na\n### Warnings\nancestor\n### Work\nwork\n#### Prerequisites\nchild\n## B\nb\n### Warnings\nunrelated"
    r = select_skill_content(doc, heading="Work")
    assert "ancestor" in r["content"] and "global" in r["content"]
    assert "unrelated" not in r["content"]
    assert "child" in r["content"]  # selected subtree is intentionally retained


def test_nested_safety_does_not_leak_between_unrelated_branches():
    doc = (
        "# Root\n"
        "## A\n"
        "### Warnings\nA-only warning\n"
        "## B\n"
        "### Work\nB work\n"
    )
    result = select_skill_content(doc, heading="Work")
    assert "B work" in result["content"]
    assert "A-only warning" not in result["content"]
    assert result["included_safety_sections"] == []


def test_following_safety_applies_only_when_contiguous():
    adjacent = select_skill_content(
        "# Root\n## Work\nwork\n## Warnings\nadjacent warning\n## Other\nother",
        heading="Work",
    )
    assert adjacent["included_safety_sections"] == ["Warnings"]
    assert "adjacent warning" in adjacent["content"]

    separated = select_skill_content(
        "# Root\n## Work\nwork\n## Other\nother\n## Warnings\nlater warning",
        heading="Work",
    )
    assert separated["included_safety_sections"] == []
    assert "later warning" not in separated["content"]


def test_fuzzy_heading_overlap_beats_body_overlap():
    doc = "## Target\nnoise noise noise\n\n## Other\nTarget target target"
    assert select_skill_content(doc, query="target")["selected_heading"] == "Target"


def test_fences_require_matching_marker_and_length_and_no_four_space_fence():
    doc = "    ## Indented\ntext\n\n~~~md\n## Fake\n```\n## Still fake\n~~~~\n\n## Real\nreal"
    r = select_skill_content(doc, heading="Real")
    assert "## Real" in r["content"]
    assert select_skill_content(doc, heading="Fake")["selected_heading"] is None
    assert select_skill_content(doc, heading="Indented")["selected_heading"] is None


def test_truncation_keeps_marker_and_heading_with_tiny_remaining_body():
    r = select_skill_content("## Heading\n" + "x" * 2000, heading="Heading", max_chars=256)
    assert r["content"].startswith("## Heading")
    assert r["content"].endswith("\n[... truncated ...]")
    assert len(r["content"]) <= 256


def test_linked_files_support_flat_metadata_and_exact_mentions_only():
    doc = "## Use\nSee [a](refs/a.md), `refs/b.md`, and refs/c.md. Not refs/ab.md.extra."
    linked = {"refs/a.md": {"x": 1}, "refs/b.md": {"x": 2}, "refs/c.md": {"x": 3}, "refs/ab.md": {"x": 4}}
    r = select_skill_content(doc, heading="Use", linked_files=linked)
    assert list(r["linked_files"]) == ["refs/a.md", "refs/b.md", "refs/c.md"]
    assert "refs/ab.md" not in r["linked_files"]
