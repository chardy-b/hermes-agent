"""Deterministic, bounded, read-only skill inventory review."""
from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Any

from agent.skill_utils import is_excluded_skill_path, parse_frontmatter

_MAX_SKILLS = 5000
_MAX_BYTES = 2_000_000
_MAX_FILES = 20_000
_MAX_BACKTEST_BYTES = 2_000_000
_MAX_BACKTEST_ITEMS = 100


def _parse(data: bytes) -> tuple[dict[str, Any], str]:
    try:
        text = data.decode("utf-8")
        fm, _ = parse_frontmatter(text[:10000])
        return (fm or {}, text)
    except (UnicodeError, ValueError, TypeError):
        return {}, ""


def _name(path: Path, fm: dict[str, Any]) -> str:
    return str(fm.get("name") or path.parent.name).strip()


def _list_value(fm: dict[str, Any], key: str) -> list[str]:
    meta = fm.get("metadata") if isinstance(fm.get("metadata"), dict) else {}
    hermes = meta.get("hermes") if isinstance(meta, dict) and isinstance(meta.get("hermes"), dict) else {}
    raw = fm.get(key) or hermes.get(key)
    if isinstance(raw, str):
        raw = raw.strip().strip("[]").split(",")
    return sorted({str(x).strip() for x in (raw if isinstance(raw, list) else []) if str(x).strip()})


def _safe_int(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _empty() -> dict[str, Any]:
    return {"skills": [], "edges": [], "duplicates": [], "stats": {
        "skills": 0, "edges": 0, "shortening_candidates": 0, "bytes_scanned": 0,
        "bytes_selected": 0, "duplicates": 0, "files_scanned": 0,
        "max_bytes": _MAX_BYTES, "max_files": _MAX_FILES, "truncated": False,
    }}


def backtest_report(current: dict[str, Any], baseline: Any) -> dict[str, Any]:
    """Return a bounded, deterministic semantic comparison of two reports."""
    out: dict[str, Any] = {"changed": False, "compatible": True, "errors": [], "warnings": [], "counts": {}}
    if not isinstance(baseline, dict) or not isinstance(current, dict):
        out["compatible"] = False; out["errors"] = ["report must be a JSON object"]; return out
    def validate(report, label):
        errors, warnings = [], []
        for key in ("skills", "edges"):
            if not isinstance(report.get(key), list):
                errors.append(f"{label}.{key} must be a list")
        if "duplicates" in report and not isinstance(report.get("duplicates"), list):
            errors.append(f"{label}.duplicates must be a list")
        skills = report.get("skills") if isinstance(report.get("skills"), list) else []
        seen = set()
        for i, row in enumerate(skills):
            if not isinstance(row, dict): errors.append(f"{label}.skills[{i}] must be an object"); continue
            name = row.get("name")
            if not isinstance(name, str) or not name.strip(): errors.append(f"{label}.skills[{i}].name must be a nonempty string")
            elif name in seen: errors.append(f"{label}.skills[{i}].name is duplicated")
            seen.add(name)
            for key in ("tags", "declared_references", "references", "protected_reasons"):
                if key in row and (not isinstance(row[key], list) or not all(isinstance(x, str) for x in row[key])): errors.append(f"{label}.skills[{i}].{key} must be a list of strings")
            for key in ("shortening_candidate", "pinned", "protected_builtin"):
                if key in row and not isinstance(row[key], bool): errors.append(f"{label}.skills[{i}].{key} must be boolean")
            for key in ("use_count", "view_count", "patch_count", "activity_count"):
                if key in row:
                    try: int(row[key])
                    except (TypeError, ValueError): warnings.append(f"{label}.skills[{i}].{key} is not numeric")
        for key, fields in (("edges", ("source", "target")), ("duplicates", ("name", "selected", "discarded"))):
            rows = report.get(key) if isinstance(report.get(key), list) else []
            for i, row in enumerate(rows):
                if not isinstance(row, dict): errors.append(f"{label}.{key}[{i}] must be an object"); continue
                for field in fields:
                    if not isinstance(row.get(field), str) or not row[field].strip(): errors.append(f"{label}.{key}[{i}].{field} must be a nonempty string")
        return errors, warnings
    base_errors, base_warnings = validate(baseline, "baseline")
    cur_errors, cur_warnings = validate(current, "current")
    out["baseline_errors"], out["baseline_warnings"] = base_errors, base_warnings
    out["errors"], out["warnings"] = cur_errors, cur_warnings
    if base_errors or cur_errors:
        out["compatible"] = False; return out
    def rows(report): return {r["name"]: r for r in report["skills"]}
    old, new = rows(baseline), rows(current)
    names = lambda xs: sorted(set(xs))
    delta: dict[str, Any] = {
        "skills_added": names(set(new) - set(old)), "skills_removed": names(set(old) - set(new)),
        "tags_changed": [], "declared_references_changed": [],
        "shortening_candidates_changed": [], "candidate_status_added": [],
        "candidate_status_removed": [], "usage_changed": [], "edges_added": [], "edges_removed": [],
    }
    for name in sorted(set(old) & set(new)):
        a, b = old[name], new[name]
        if sorted(a.get("tags", [])) != sorted(b.get("tags", [])): delta["tags_changed"].append(name)
        if sorted(a.get("declared_references", a.get("references", []))) != sorted(b.get("declared_references", b.get("references", []))): delta["declared_references_changed"].append(name)
        ac, bc = bool(a.get("shortening_candidate")), bool(b.get("shortening_candidate"))
        if ac != bc: delta["shortening_candidates_changed"].append(name)
        if not ac and bc: delta["candidate_status_added"].append(name)
        if ac and not bc: delta["candidate_status_removed"].append(name)
        if any(_safe_int(a.get(k)) != _safe_int(b.get(k)) for k in ("use_count", "view_count", "patch_count", "activity_count")):
            delta["usage_changed"].append(name)
    edges = lambda r: {(e["source"], e["target"]) for e in r["edges"]}
    delta["edges_added"] = sorted(edges(current) - edges(baseline))
    delta["edges_removed"] = sorted(edges(baseline) - edges(current))
    def tail(path):
        parts = path.replace("\\", "/").split("/"); return "/".join(parts[-3:])
    old_dups = {(d["name"], tail(d["selected"]), tail(d["discarded"])) for d in baseline.get("duplicates", [])}
    new_dups = {(d["name"], tail(d["selected"]), tail(d["discarded"])) for d in current.get("duplicates", [])}
    delta["duplicates_added"] = sorted(new_dups - old_dups)
    delta["duplicates_removed"] = sorted(old_dups - new_dups)
    for key in ("truncated",):
        if bool(baseline.get("stats", {}).get(key)) != bool(current.get("stats", {}).get(key)): delta[key + "_changed"] = True
    for key in ("pinned", "protected_builtin", "protected_reasons"):
        delta[key + "_changed"] = sorted(n for n in set(old) & set(new) if old[n].get(key) != new[n].get(key))
    out["deltas"] = {k: sorted(v) if isinstance(v, list) else v for k, v in delta.items()}
    out["counts"] = {k: (len(v) if isinstance(v, list) else int(bool(v))) for k, v in out["deltas"].items()}
    out["deltas_truncated"] = {k: n > _MAX_BACKTEST_ITEMS for k, n in out["counts"].items()}
    out["total_counts"] = out["counts"].copy()
    out["deltas"] = {k: (v[:_MAX_BACKTEST_ITEMS] if isinstance(v, list) else v) for k, v in out["deltas"].items()}
    out["changed"] = any(out["counts"].values())
    return out


def load_baseline(path: Path) -> tuple[Any, str | None]:
    try:
        if path.stat().st_size > _MAX_BACKTEST_BYTES: return None, "baseline exceeds 2MB limit"
        return json.loads(path.read_text(encoding="utf-8")), None
    except FileNotFoundError: return None, "baseline file not found"
    except (OSError, UnicodeError, json.JSONDecodeError) as exc: return None, f"invalid baseline: {exc}"


def review_skills(roots: list[Path], usage: dict[str, dict[str, Any]] | None = None,
                  max_skills: int = _MAX_SKILLS) -> dict[str, Any]:
    max_skills = max(0, min(_MAX_SKILLS, _safe_int(max_skills)))
    if not max_skills:
        return _empty()
    if usage is None:
        try:
            from tools.skill_usage import load_usage
            usage = load_usage()
        except Exception:
            usage = {}
    selected: dict[str, tuple[Path, dict[str, Any], str, int]] = {}
    # Every accepted file is parsed exactly once during the bounded scan.  Keep
    # its parsed metadata for duplicate reporting; never reread paths afterward.
    scanned: list[tuple[Path, str, dict[str, Any]]] = []
    seen: set[Path] = set()
    bytes_scanned = files_scanned = 0
    truncated = False
    # Root order and sorted os.walk order are resolution order; never replace a winner.
    for root in roots:
        root = Path(root)
        if not root.exists():
            continue
        for directory, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if not is_excluded_skill_path(Path(directory) / d / "SKILL.md"))
            if "SKILL.md" not in files:
                continue
            path = Path(directory) / "SKILL.md"
            if path in seen or is_excluded_skill_path(path):
                continue
            if files_scanned >= _MAX_FILES:
                truncated = True; break
            try:
                size = path.stat().st_size
                if bytes_scanned + size > _MAX_BYTES:
                    truncated = True; break
                data = path.read_bytes()
            except (OSError, UnicodeError):
                continue
            files_scanned += 1; bytes_scanned += len(data)
            fm, text = _parse(data); name = _name(path, fm)
            seen.add(path)
            scanned.append((path, name, fm))
            if name and name not in selected and len(selected) < max_skills:
                selected[name] = (path, fm, text, len(data))
        if truncated:
            break
    # Duplicate diagnostics are emitted from the bounded scan against the
    # final selected definition; no post-scan filesystem reads are permitted.
    duplicates = [
        {"name": name, "discarded": str(path), "selected": str(selected[name][0])}
        for path, name, _fm in scanned
        if path != selected.get(name, (None,))[0] and name in selected
    ]
    try:
        from tools.skill_usage import activity_count, is_protected_builtin
    except Exception:
        activity_count = lambda u: sum(_safe_int(u.get(k)) for k in ("use_count", "view_count", "patch_count"))
        is_protected_builtin = lambda n: False
    known = set(selected)
    records = []
    bytes_selected = 0
    for name in sorted(known):
        path, fm, text, size = selected[name]; bytes_selected += size
        u = usage.get(name) or {}; activity = activity_count(u); protected = is_protected_builtin(name)
        refs = sorted(set(_list_value(fm, "related_skills")) & known)
        callers = []
        row = {"name": name, "path": str(path), "tags": sorted(set(x.lower() for x in _list_value(fm, "tags"))),
               "lines": text.count("\n") + 1, "bytes": size, "use_count": _safe_int(u.get("use_count")),
               "view_count": _safe_int(u.get("view_count")), "patch_count": _safe_int(u.get("patch_count")),
               "activity_count": activity, "pinned": bool(u.get("pinned")), "protected_builtin": protected,
               "references": refs, "declared_references": refs, "heuristic_references": [], "callers": callers}
        records.append(row)
    by_name = {r["name"]: r for r in records}
    for r in records:
        for target in r["references"]:
            by_name[target]["callers"].append(r["name"])
    candidates = 0
    for r in records:
        r["callers"].sort(); reasons = (["pinned"] if r["pinned"] else []) + (["protected_builtin"] if r["protected_builtin"] else [])
        if r["activity_count"] >= 10 or r["use_count"] >= 5: reasons.append("frequent")
        r["protected_reasons"] = reasons; r["shortening_candidate"] = r["lines"] >= 500 and not reasons and not r["callers"]
        r["shortening_reason"] = "large and has no skill callers; review for reference extraction" if r["shortening_candidate"] else None
        candidates += r["shortening_candidate"]
    return {"skills": records, "edges": [{"source": r["name"], "target": t} for r in records for t in r["references"]],
            "duplicates": sorted(duplicates, key=lambda d: (d["name"], d["discarded"])),
            "stats": {"skills": len(records), "edges": sum(len(r["references"]) for r in records), "shortening_candidates": candidates,
                      "bytes_scanned": bytes_scanned, "bytes_selected": bytes_selected, "duplicates": len(duplicates),
                      "files_scanned": files_scanned, "max_bytes": _MAX_BYTES, "max_files": _MAX_FILES, "truncated": truncated}}
