from __future__ import annotations

import argparse
import json
from types import SimpleNamespace


def _report():
    return {
        "skills": [
            {
                "name": "busy",
                "activity_count": 12,
                "shortening_candidate": False,
            },
            {
                "name": "large",
                "activity_count": 0,
                "shortening_candidate": True,
            },
        ],
        "edges": [],
        "duplicates": [
            {"name": "shared", "discarded": "/external/shared/SKILL.md", "selected": "/local/shared/SKILL.md"}
        ],
        "stats": {
            "skills": 2,
            "edges": 0,
            "shortening_candidates": 1,
            "duplicates": 1,
            "bytes_scanned": 20,
            "bytes_selected": 10,
            "files_scanned": 3,
            "max_bytes": 100,
            "max_files": 10,
            "truncated": True,
        },
    }


def test_review_command_is_registered():
    import hermes_cli.curator as curator_cli

    parser = argparse.ArgumentParser(prog="hermes curator")
    curator_cli.register_cli(parser)
    args = parser.parse_args(["review", "--max-skills", "7", "--json"])
    assert args.func is curator_cli._cmd_review
    assert args.max_skills == 7
    assert args.json is True
    assert args.baseline is None

    baseline_args = parser.parse_args(["review", "--baseline", "/tmp/baseline.json"])
    assert baseline_args.baseline == "/tmp/baseline.json"


def test_review_human_output_is_bounded_and_actionable(monkeypatch, capsys):
    import agent.skill_reviewer as reviewer
    import agent.skill_utils as skill_utils
    import hermes_cli.curator as curator_cli

    roots = ["/local", "/external"]
    captured = {}
    monkeypatch.setattr(skill_utils, "get_all_skills_dirs", lambda: roots)

    def fake_review(actual_roots, max_skills):
        captured["roots"] = actual_roots
        captured["max_skills"] = max_skills
        return _report()

    monkeypatch.setattr(reviewer, "review_skills", fake_review)
    assert curator_cli._cmd_review(SimpleNamespace(max_skills=9, json=False)) == 0
    output = capsys.readouterr().out
    assert captured == {"roots": roots, "max_skills": 9}
    assert "truncated: True" in output
    assert "duplicate: shared" in output
    assert "frequent: busy activity=12" in output
    assert "candidate: large" in output


def test_review_json_output_is_deterministic(monkeypatch, capsys):
    import agent.skill_reviewer as reviewer
    import agent.skill_utils as skill_utils
    import hermes_cli.curator as curator_cli

    monkeypatch.setattr(skill_utils, "get_all_skills_dirs", lambda: ["/local"])
    monkeypatch.setattr(reviewer, "review_skills", lambda roots, max_skills: _report())
    assert curator_cli._cmd_review(SimpleNamespace(max_skills=5, json=True)) == 0
    output = capsys.readouterr().out.strip()
    assert json.loads(output) == _report()
    assert output == json.dumps(_report(), sort_keys=True, separators=(",", ":"))


def test_review_baseline_json_and_human_output(monkeypatch, tmp_path, capsys):
    import agent.skill_reviewer as reviewer
    import agent.skill_utils as skill_utils
    import hermes_cli.curator as curator_cli

    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(_report()), encoding="utf-8")
    monkeypatch.setattr(skill_utils, "get_all_skills_dirs", lambda: ["/local"])
    monkeypatch.setattr(reviewer, "review_skills", lambda roots, max_skills: _report())

    args = SimpleNamespace(max_skills=5, json=True, baseline=str(baseline))
    assert curator_cli._cmd_review(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["backtest"]["compatible"] is True
    assert payload["backtest"]["changed"] is False

    args.json = False
    assert curator_cli._cmd_review(args) == 0
    assert "backtest: changed=False compatible=True" in capsys.readouterr().out


def test_review_missing_and_oversized_baselines_are_structured(monkeypatch, tmp_path, capsys):
    import agent.skill_reviewer as reviewer
    import agent.skill_utils as skill_utils
    import hermes_cli.curator as curator_cli

    monkeypatch.setattr(skill_utils, "get_all_skills_dirs", lambda: ["/local"])
    monkeypatch.setattr(reviewer, "review_skills", lambda roots, max_skills: _report())

    missing = tmp_path / "missing.json"
    args = SimpleNamespace(max_skills=5, json=True, baseline=str(missing))
    assert curator_cli._cmd_review(args) == 0
    result = json.loads(capsys.readouterr().out)["backtest"]
    assert result["compatible"] is False
    assert result["errors"] == ["baseline file not found"]

    oversized = tmp_path / "large.json"
    oversized.write_bytes(b" " * (reviewer._MAX_BACKTEST_BYTES + 1))
    args.baseline = str(oversized)
    assert curator_cli._cmd_review(args) == 0
    result = json.loads(capsys.readouterr().out)["backtest"]
    assert result["compatible"] is False
    assert "exceeds" in result["errors"][0]
