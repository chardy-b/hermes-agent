import json
import pytest

from agent.skill_retrieval_evaluation import evaluate_retrieval_scenarios, render_evaluation_markdown


def test_evaluation_is_deterministic_and_reports_parent_peak_separately():
    scenarios = [{"name": "router", "baseline_payload": "safety environment lifecycle verification " + "X" * 1000,
                  "projected_payload": "safety environment lifecycle verification", "required_markers": ["safety", "verification"],
                  "forbidden_markers": ["SECRET"], "invariants": {"safety": "safety", "environment": "environment", "lifecycle": "lifecycle", "verification": "verification"}, "latency_ms": 12}]
    first = evaluate_retrieval_scenarios(scenarios)
    assert first == evaluate_retrieval_scenarios(json.loads(json.dumps(scenarios)))
    a = first["aggregate"]
    assert a["all_correct"] and a["all_safe"] and a["no_leakage"]
    assert a["parent_peak_context"] == a["total_parent_tokens"]
    assert a["tool_result_bytes"] == len(scenarios[0]["projected_payload"].encode())
    assert "# Skill retrieval evaluation" in render_evaluation_markdown(first)


@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        [{"name": "x"}],
        [
            {
                "name": "x",
                "baseline_payload": 1,
                "projected_payload": "",
                "required_markers": [],
                "forbidden_markers": [],
                "invariants": {},
            }
        ],
        [
            {
                "name": "x",
                "baseline_payload": "a",
                "projected_payload": "b",
                "required_markers": [],
                "forbidden_markers": [],
                "invariants": {"safety": ["not", "flat"]},
            }
        ],
        [
            {
                "name": "x",
                "baseline_payload": "a",
                "projected_payload": "b",
                "required_markers": [],
                "forbidden_markers": [],
                "invariants": {},
                "latency_ms": True,
            }
        ],
    ],
)
def test_malformed_inputs_raise_value_error(bad):
    with pytest.raises(ValueError):
        evaluate_retrieval_scenarios(bad)
