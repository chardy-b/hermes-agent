from pathlib import Path

import pytest

from agent import skill_reviewer
from agent.skill_reviewer import backtest_report, load_baseline, review_skills


def _skill(
    root: Path,
    directory: str,
    *,
    name: str | None = None,
    body: str = "small",
    tags: tuple[str, ...] = (),
    related: tuple[str, ...] = (),
) -> Path:
    path = root / directory
    path.mkdir(parents=True, exist_ok=True)
    skill_name = name or directory
    tag_text = ", ".join(tags)
    related_text = ", ".join(related)
    (path / "SKILL.md").write_text(
        "---\n"
        f"name: {skill_name}\n"
        "metadata:\n"
        "  hermes:\n"
        f"    tags: [{tag_text}]\n"
        f"    related_skills: [{related_text}]\n"
        "---\n"
        f"{body}\n",
        encoding="utf-8",
    )
    return path / "SKILL.md"


def _row(report, name):
    return next(row for row in report["skills"] if row["name"] == name)


def test_backtest_reports_semantic_deltas_and_ignores_paths_and_stats():
    old = {"skills": [{"name": "a", "tags": ["one"], "declared_references": ["b"],
                       "shortening_candidate": False, "use_count": 1}],
           "edges": [{"source": "a", "target": "b"}],
           "stats": {"bytes_scanned": 1, "files_scanned": 1}}
    new = {"skills": [{"name": "a", "path": "/new", "tags": ["two"],
                       "declared_references": [], "shortening_candidate": True,
                       "use_count": 2}, {"name": "c"}],
           "edges": [{"source": "a", "target": "c"}],
           "stats": {"bytes_scanned": 999, "files_scanned": 99}}
    result = backtest_report(new, old)
    assert result["changed"] is True
    assert result["deltas"]["skills_added"] == ["c"]
    assert result["deltas"]["skills_removed"] == []
    assert result["deltas"]["shortening_candidates_changed"] == ["a"]
    assert result["deltas"]["usage_changed"] == ["a"]
    assert result["deltas"]["edges_added"] == [("a", "c")]
    assert result["deltas"]["edges_removed"] == [("a", "b")]
    assert result["compatible"] is True


def test_backtest_validates_schema_and_reports_semantic_status_changes(monkeypatch):
    baseline = {
        "skills": [{
            "name": "a", "tags": [], "declared_references": [],
            "shortening_candidate": False, "pinned": False,
            "protected_builtin": False, "protected_reasons": [],
        }],
        "edges": [],
        "duplicates": [{
            "name": "shared", "selected": "/old/local/shared/SKILL.md",
            "discarded": "/old/external/shared/SKILL.md",
        }],
        "stats": {"truncated": False, "errors": ["old-error"], "warnings": ["old-warning"]},
    }
    current = {
        "skills": [{
            "name": "a", "tags": [], "declared_references": [],
            "shortening_candidate": False, "pinned": True,
            "protected_builtin": True, "protected_reasons": ["pinned", "protected_builtin"],
        }],
        "edges": [],
        "duplicates": [],
        "stats": {"truncated": True},
    }
    result = backtest_report(current, baseline)
    assert result["compatible"] is True
    assert result["deltas"]["truncated_changed"] is True
    assert result["deltas"]["pinned_changed"] == ["a"]
    assert result["deltas"]["protected_builtin_changed"] == ["a"]
    assert result["deltas"]["protected_reasons_changed"] == ["a"]
    assert result["deltas"]["duplicates_removed"]
    assert result["baseline_errors"] == []
    assert result["baseline_warnings"] == []
    assert result["errors"] == []

    malformed = backtest_report(current, {"skills": [], "edges": [{"source": "a", "target": None}]})
    assert malformed["compatible"] is False
    assert any("target must be a nonempty string" in error for error in malformed["baseline_errors"])


@pytest.mark.parametrize("side", ["baseline", "current"])
def test_backtest_rejects_non_object_stats_without_crashing(side):
    valid = {"skills": [], "edges": [], "duplicates": [], "stats": {}}
    malformed = {**valid, "stats": "bad"}
    current = malformed if side == "current" else valid
    baseline = malformed if side == "baseline" else valid
    result = backtest_report(current, baseline)
    assert result["compatible"] is False
    errors = result["errors"] if side == "current" else result["baseline_errors"]
    assert errors == [f"{side}.stats must be an object"]


def test_backtest_bounds_deltas_and_exposes_total_counts(monkeypatch):
    monkeypatch.setattr(skill_reviewer, "_MAX_BACKTEST_ITEMS", 2)
    baseline = {"skills": [], "edges": [], "duplicates": []}
    current = {
        "skills": [{"name": name} for name in ("a", "b", "c")],
        "edges": [],
        "duplicates": [],
    }
    result = backtest_report(current, baseline)
    assert result["deltas"]["skills_added"] == ["a", "b"]
    assert result["total_counts"]["skills_added"] == 3
    assert result["deltas_truncated"]["skills_added"] is True


def test_backtest_reference_change_covers_derived_caller_semantics():
    baseline = {
        "skills": [{"name": "a", "declared_references": ["b"]}, {"name": "b"}],
        "edges": [{"source": "a", "target": "b"}],
        "duplicates": [],
    }
    current = {
        "skills": [{"name": "a", "declared_references": []}, {"name": "b"}],
        "edges": [],
        "duplicates": [],
    }
    result = backtest_report(current, baseline)
    assert result["deltas"]["declared_references_changed"] == ["a"]
    assert result["deltas"]["edges_removed"] == [("a", "b")]


def test_baseline_loader_handles_missing_malformed_and_oversized(tmp_path):
    missing, error = load_baseline(tmp_path / "missing.json")
    assert missing is None and error is not None and "not found" in error
    malformed_path = tmp_path / "bad.json"
    malformed_path.write_text("not json", encoding="utf-8")
    malformed, error = load_baseline(malformed_path)
    assert malformed is None and error is not None and "invalid baseline" in error
    huge = tmp_path / "huge.json"
    huge.write_bytes(b"x" * (skill_reviewer._MAX_BACKTEST_BYTES + 1))
    value, error = load_baseline(huge)
    assert value is None and error is not None and "exceeds" in error


def test_structured_relations_build_edges_and_callers_but_prose_does_not(tmp_path):
    _skill(tmp_path, "alpha", body="Mention beta in ordinary prose.", tags=("One", "two"), related=("beta",))
    _skill(tmp_path, "beta")
    report = review_skills([tmp_path], usage={})

    assert _row(report, "alpha")["tags"] == ["one", "two"]
    assert _row(report, "alpha")["references"] == ["beta"]
    assert _row(report, "beta")["callers"] == ["alpha"]
    assert report["edges"] == [{"source": "alpha", "target": "beta"}]

    _skill(tmp_path, "alpha", body="Mention beta in ordinary prose.")
    report = review_skills([tmp_path], usage={})
    assert _row(report, "alpha")["references"] == []


def test_first_root_wins_and_all_duplicate_diagnostics_use_final_winner(tmp_path):
    local = tmp_path / "local"
    ext1 = tmp_path / "ext1"
    ext2 = tmp_path / "ext2"
    ext3 = tmp_path / "ext3"
    selected = _skill(local, "winner", name="shared", related=("target",))
    _skill(local, "target")
    for index, root in enumerate((ext1, ext2, ext3), 1):
        _skill(root, f"copy-{index}", name="shared", related=())

    report = review_skills([local, ext1, ext2, ext3], usage={})
    assert _row(report, "shared")["path"] == str(selected)
    assert _row(report, "shared")["references"] == ["target"]
    assert len(report["duplicates"]) == 3
    assert {item["selected"] for item in report["duplicates"]} == {str(selected)}
    assert {item["discarded"] for item in report["duplicates"]} == {
        str(ext1 / "copy-1" / "SKILL.md"),
        str(ext2 / "copy-2" / "SKILL.md"),
        str(ext3 / "copy-3" / "SKILL.md"),
    }


def test_max_skills_limits_unique_names_but_scanned_duplicate_is_reported(tmp_path):
    local = tmp_path / "local"
    external = tmp_path / "external"
    winner = _skill(local, "a")
    _skill(local, "b")
    duplicate = _skill(external, "copy", name="a")

    report = review_skills([local, external], usage={}, max_skills=1)
    assert [row["name"] for row in report["skills"]] == ["a"]
    assert report["duplicates"] == [{"name": "a", "discarded": str(duplicate), "selected": str(winner)}]


def test_malformed_data_is_safe_and_protection_blocks_candidates(tmp_path):
    _skill(tmp_path, "alpha", body="x\n" * 500)
    _skill(tmp_path, "plan", body="x\n" * 500)
    malformed = tmp_path / "malformed"
    malformed.mkdir()
    (malformed / "SKILL.md").write_text("---\n: invalid: [\n---\nbody\n", encoding="utf-8")

    report = review_skills(
        [tmp_path],
        usage={"alpha": {"use_count": "bad", "view_count": 2, "patch_count": 3, "pinned": True}},
    )
    alpha = _row(report, "alpha")
    assert alpha["activity_count"] == 5
    assert "pinned" in alpha["protected_reasons"]
    assert alpha["shortening_candidate"] is False
    plan = _row(report, "plan")
    assert plan["protected_builtin"] is True
    assert plan["shortening_candidate"] is False
    assert _row(report, "malformed")["name"] == "malformed"


@pytest.mark.parametrize("limit_name,limit_value", [("_MAX_FILES", 1), ("_MAX_BYTES", 1)])
def test_hard_scan_limits_are_reported_and_never_reread(monkeypatch, tmp_path, limit_name, limit_value):
    _skill(tmp_path, "a")
    _skill(tmp_path, "b")
    monkeypatch.setattr(skill_reviewer, limit_name, limit_value)
    reads = 0
    original = Path.read_bytes

    def counted(path):
        nonlocal reads
        reads += 1
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", counted)
    report = review_skills([tmp_path], usage={})
    assert report["stats"]["truncated"] is True
    assert reads == report["stats"]["files_scanned"]
    assert report["stats"]["files_scanned"] <= 1


def test_review_is_deterministic_and_zero_or_negative_limit_is_empty(tmp_path):
    _skill(tmp_path, "a")
    _skill(tmp_path, "b")
    first = review_skills([tmp_path], usage={}, max_skills=1)
    second = review_skills([tmp_path], usage={}, max_skills=1)
    assert first == second
    assert first["stats"]["skills"] == 1
    assert review_skills([tmp_path], usage={}, max_skills=-1)["skills"] == []


def test_representative_repository_tree_satisfies_graph_and_bound_invariants(monkeypatch):
    root = Path(__file__).resolve().parents[2] / "skills"
    monkeypatch.setattr(skill_reviewer, "_MAX_BYTES", 10_000_000)
    report = review_skills([root], usage={}, max_skills=25)

    names = [row["name"] for row in report["skills"]]
    assert names == sorted(set(names))
    assert 0 < len(names) <= 25
    assert report["stats"]["skills"] == len(names)
    assert report["stats"]["bytes_selected"] <= report["stats"]["bytes_scanned"]
    assert all(edge["source"] != edge["target"] for edge in report["edges"])
    assert all(Path(row["path"]).is_file() for row in report["skills"])
