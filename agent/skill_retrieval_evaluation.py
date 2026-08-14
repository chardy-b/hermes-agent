"""Deterministic behavioral reports for progressive skill retrieval fixtures."""
from __future__ import annotations

from typing import Any

from agent.model_metadata import estimate_tokens_rough

_REQUIRED = ("name", "baseline_payload", "projected_payload", "required_markers", "forbidden_markers", "invariants")


def _validate(s: Any, i: int) -> None:
    if not isinstance(s, dict):
        raise ValueError(f"scenario[{i}] must be an object")
    missing = [k for k in _REQUIRED if k not in s]
    if missing:
        raise ValueError(f"scenario[{i}] missing required fields: {', '.join(missing)}")
    if not isinstance(s["name"], str) or not s["name"]:
        raise ValueError(f"scenario[{i}].name must be a non-empty string")
    for key in ("baseline_payload", "projected_payload"):
        if not isinstance(s[key], str):
            raise ValueError(f"scenario[{i}].{key} must be a string")
    for key in ("required_markers", "forbidden_markers"):
        if not isinstance(s[key], list) or not all(isinstance(x, str) and x for x in s[key]):
            raise ValueError(f"scenario[{i}].{key} must be a list of non-empty strings")
    if (
        not isinstance(s["invariants"], dict)
        or not all(
            isinstance(key, str)
            and key
            and isinstance(value, str)
            and value
            for key, value in s["invariants"].items()
        )
    ):
        raise ValueError(
            f"scenario[{i}].invariants must map non-empty strings to non-empty strings"
        )
    if "latency_ms" in s and (
        isinstance(s["latency_ms"], bool)
        or not isinstance(s["latency_ms"], (int, float))
        or s["latency_ms"] < 0
    ):
        raise ValueError(f"scenario[{i}].latency_ms must be a non-negative number")


def evaluate_retrieval_scenarios(scenarios: list[dict]) -> dict:
    if not isinstance(scenarios, list):
        raise ValueError("scenarios must be a list")
    rows = []
    for i, s in enumerate(scenarios):
        _validate(s, i)
        base, projected = s["baseline_payload"], s["projected_payload"]
        required = {m: m in projected for m in s["required_markers"]}
        visible = {k: (not v or str(v) in projected) for k, v in s["invariants"].items()}
        forbidden = {m: m not in projected for m in s["forbidden_markers"]}
        bc, pc = len(base), len(projected)
        bt, pt = estimate_tokens_rough(base), estimate_tokens_rough(projected)
        rows.append({"name": s["name"], "baseline_chars": bc, "baseline_tokens": bt,
                     "projected_chars": pc, "projected_tokens": pt,
                     "saved_chars": bc-pc, "saved_tokens": bt-pt,
                     "saved_percent": round((bc-pc) * 100 / bc, 2) if bc else 0.0,
                     "saved_token_percent": round((bt-pt) * 100 / bt, 2) if bt else 0.0,
                     "correctness_markers_preserved": all(required.values()),
                     "required_markers": required, "safety_invariants_visible": all(visible.values()),
                     "invariants": visible, "forbidden_leakage_absent": all(forbidden.values()),
                     "forbidden_markers": forbidden, "latency_ms": s.get("latency_ms")})
    baseline_chars = sum(r["baseline_chars"] for r in rows); projected_chars = sum(r["projected_chars"] for r in rows)
    baseline_tokens = sum(r["baseline_tokens"] for r in rows); projected_tokens = sum(r["projected_tokens"] for r in rows)
    return {"scenarios": rows, "aggregate": {"scenario_count": len(rows), "total_baseline_chars": baseline_chars,
        "total_projected_chars": projected_chars, "total_saved_chars": baseline_chars-projected_chars,
        "total_baseline_tokens": baseline_tokens, "total_projected_tokens": projected_tokens,
        "total_saved_tokens": baseline_tokens-projected_tokens,
        "savings_percent": round((baseline_chars-projected_chars)*100/baseline_chars, 2) if baseline_chars else 0.0,
        "all_correct": all(r["correctness_markers_preserved"] for r in rows), "all_safe": all(r["safety_invariants_visible"] for r in rows),
        "no_leakage": all(r["forbidden_leakage_absent"] for r in rows), "max_projected_chars": max((r["projected_chars"] for r in rows), default=0),
        "parent_peak_context": max((r["projected_tokens"] for r in rows), default=0), "total_parent_tokens": projected_tokens,
        "tool_result_bytes": sum(len(s["projected_payload"].encode("utf-8")) for s in scenarios)}}


def render_evaluation_markdown(report: dict) -> str:
    a = report["aggregate"]
    lines = ["# Skill retrieval evaluation", "", f"Scenarios: {a['scenario_count']}", f"Savings: {a['savings_percent']:.2f}%", f"Correct: {a['all_correct']}", f"Safe: {a['all_safe']}", f"No leakage: {a['no_leakage']}", "", "| Scenario | Baseline chars | Projected chars | Saved % | Correct | Safe | No leakage |", "|---|---:|---:|---:|---|---|---|"]
    lines += [f"| {r['name']} | {r['baseline_chars']} | {r['projected_chars']} | {r['saved_percent']:.2f}% | {r['correctness_markers_preserved']} | {r['safety_invariants_visible']} | {r['forbidden_leakage_absent']} |" for r in report["scenarios"]]
    return "\n".join(lines) + "\n"
