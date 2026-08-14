"""Deterministic, bounded Markdown skill-section retrieval.

Sections include their heading-level subtree. Safety support is limited to
ancestor safety, preceding same-parent safety, and document-global safety
before the first operational sibling.
"""
from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass
from collections.abc import Callable

@dataclass
class _Section:
    heading: str
    level: int
    start: int
    end: int
    text: str
    ancestry: tuple[int, ...]

_ATX = re.compile(r"^( {0,3})(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$")
_TOKEN = re.compile(r"[a-z0-9]+")
_MARKER = "\n[... truncated ...]"
_SAFETY = {"prerequisites", "warnings"}

def _sections(content: str) -> list[_Section]:
    found = []
    stack: list[tuple[int, int]] = []
    pos = 0
    fence: tuple[str, int] | None = None
    for line in content.splitlines(keepends=True):
        raw = line.rstrip("\r\n")
        lead = len(raw) - len(raw.lstrip(" "))
        if fence:
            marker, size = fence
            if lead <= 3 and raw.lstrip().startswith(marker) and len(raw.lstrip()) - len(raw.lstrip(marker)) >= size:
                fence = None
        elif lead <= 3:
            stripped = raw[lead:]
            if stripped.startswith(("`", "~")):
                char = stripped[0]
                run = len(stripped) - len(stripped.lstrip(char))
                if run >= 3:
                    fence = (char, run)
            m = _ATX.match(raw)
            if m:
                level = len(m.group(2))
                while stack and stack[-1][0] >= level:
                    stack.pop()
                ancestry = tuple(i for _, i in stack)
                found.append([pos, level, m.group(3).strip(), ancestry])
                stack.append((level, len(found)-1))
        pos += len(line)
    out = []
    for i, (start, level, heading, ancestry) in enumerate(found):
        end = len(content)
        for nxt in found[i+1:]:
            if nxt[1] <= level:
                end = nxt[0]
                break
        out.append(_Section(heading, level, start, end, content[start:end].strip(), ancestry))
    return out

def _safety_for(selected: _Section, sections: list[_Section]) -> list[_Section]:
    """Return safety sections structurally attached to the selected lineage.

    A safety section applies when it is an ancestor of the selection or a
    contiguous safety sibling immediately before/after the selected section or
    one of its ancestors. This permits router-wide safety beside a top-level
    procedure while preventing safety nested under an unrelated branch from
    leaking across the tree.
    """
    selected_index = sections.index(selected)
    lineage = (*selected.ancestry, selected_index)
    applicable: set[int] = {
        index
        for index in selected.ancestry
        if sections[index].heading.casefold() in _SAFETY
    }

    for target_index in lineage:
        target = sections[target_index]
        siblings = [
            index
            for index, section in enumerate(sections)
            if section.ancestry == target.ancestry
        ]
        position = siblings.index(target_index)
        for direction in (-1, 1):
            cursor = position + direction
            while 0 <= cursor < len(siblings):
                sibling_index = siblings[cursor]
                if sections[sibling_index].heading.casefold() not in _SAFETY:
                    break
                applicable.add(sibling_index)
                cursor += direction

    return [
        section
        for index, section in enumerate(sections)
        if index in applicable and section is not selected
    ]

def _normalize_links(linked):
    if not linked: return {}
    if all(isinstance(v, list) for v in linked.values()):
        return {p: v for group in linked.values() for p, v in ((x, None) if isinstance(x,str) else (x.get('path'), x) for x in group) if p}
    return dict(linked)

def _mentioned_link_paths(text: str, available: set[str]) -> set[str]:
    """Return exact linked-file paths referenced in Markdown or plain text."""
    candidates: set[str] = set()
    candidates.update(re.findall(r"\]\(([^)\s]+)(?:\s+[^)]*)?\)", text))
    candidates.update(re.findall(r"`([^`\n]+)`", text))
    for token in re.findall(r"\S+", text):
        candidate = token.strip("<>()[]{}'\"`,;:!?")
        if candidate.endswith(".") and candidate[:-1] in available:
            candidate = candidate[:-1]
        candidates.add(candidate)
    return available & candidates


def select_skill_content(content: str, *, heading: str | None = None, query: str | None = None, max_chars: int = 8000, linked_files: dict | None = None) -> dict:
    if not 256 <= max_chars <= 50000: raise ValueError("max_chars must be between 256 and 50000")
    sections=_sections(content); norm=lambda s: re.sub(r"\s+", " ", s.strip()).casefold(); selected=None; match_type="fallback"
    if heading is not None:
        selected=next((s for s in sections if norm(s.heading)==norm(heading)),None); match_type="exact" if selected else "fallback"
    elif query:
        q=set(_TOKEN.findall(query.casefold())); candidates=[]
        for i,s in enumerate(sections):
            h=set(_TOKEN.findall(s.heading.casefold())); b=set(_TOKEN.findall(s.text.casefold()))-h
            if q & h: candidates.append((-(len(q&h)), -s.level, i, s))
            elif not q & h and q & b: candidates.append((0, 0, i, s))
        if candidates: selected=sorted(candidates,key=lambda x:x[:3])[0][3]; match_type="fuzzy"
    supports=_safety_for(selected,sections) if selected else []
    chosen=[selected]+supports if selected else []
    raw="\n\n".join(s.text for s in chosen) if selected else (("# Skill sections\n\n"+"\n".join(f"- {s.heading}" for s in sections)) if sections else content)
    truncated=len(raw)>max_chars
    if truncated:
        head=(selected.text.splitlines()[0]+"\n") if selected else ""
        avail=max_chars-len(_MARKER)
        raw=(head+raw[max(0, len(head)):max(0,len(head)+max(0,avail-len(head)))]+_MARKER) if head and len(head)<avail else raw[:avail]+_MARKER
    returned=raw[:max_chars]; links=_normalize_links(linked_files)
    mentioned_paths = _mentioned_link_paths(returned, set(links))
    mentioned = {path: value for path, value in links.items() if path in mentioned_paths}
    omitted=[s.heading for s in sections if s not in chosen]
    return {"selected_heading":selected.heading if selected else None,"match_type":match_type,"content":returned,"content_hash":hashlib.sha256(content.encode()).hexdigest(),"returned_chars":len(returned),"total_chars":len(content),"omitted_sections":omitted,"omitted_count":len(omitted),"truncated":truncated,"included_safety_sections":[s.heading for s in supports],"linked_files":mentioned}


# Pure skill composition contract. The loader is deliberately injected: this
# module never reads files and therefore remains safe to use during routing.
_ID = re.compile(r"^[A-Za-z0-9_.:/-]+$")
_CATEGORIES = ("safety", "environment", "lifecycle", "verification")
DEFAULT_COMPOSITION_DEPTH = 2
HARD_COMPOSITION_DEPTH = 4
MAX_COMPOSITION_CHILDREN = 64
MAX_COMPOSITION_CONTENT_CHARS = 2_000_000
MAX_COMPOSITION_VISITS = 256


def _valid_composition_id(value: object) -> bool:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        return False
    return all(segment not in {"", ".", ".."} for segment in value.split("/"))


def _composition_error(code: str, **extra) -> dict:
    return {"success": False, "error": code, "error_code": code, **extra}


def _composition_source(frontmatter: dict) -> tuple[object, list[str], bool]:
    metadata = frontmatter.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        return None, [], False
    hermes = metadata.get("hermes") if isinstance(metadata, dict) else None
    if hermes is not None and not isinstance(hermes, dict):
        return None, [], False
    canonical = hermes.get("composition") if isinstance(hermes, dict) else None
    alias = frontmatter.get("composition")
    diagnostics = []
    if canonical is not None and alias is not None and canonical != alias:
        diagnostics.append("composition_alias_ignored")
    return (canonical if canonical is not None else alias), diagnostics, True


def _parse_invariants(raw: object) -> dict | None:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict) or any(key not in _CATEGORIES for key in raw):
        return None
    parsed: dict[str, list[str]] = {}
    for category in _CATEGORIES:
        values = raw.get(category, [])
        if not isinstance(values, list):
            return None
        normalized = []
        for value in values:
            if not isinstance(value, str) or not value.strip():
                return None
            cleaned = value.strip()
            if cleaned not in normalized:
                normalized.append(cleaned)
        parsed[category] = normalized
    return parsed


def parse_composition_metadata(frontmatter: dict) -> dict:
    """Normalize and validate namespaced or legacy composition metadata."""
    if not isinstance(frontmatter, dict):
        return _composition_error("composition_invalid_metadata")
    raw, diagnostics, source_valid = _composition_source(frontmatter)
    if not source_valid:
        return _composition_error("composition_invalid_metadata")
    if raw is None:
        raw = {"type": "flat"}
    if not isinstance(raw, dict):
        return _composition_error("composition_invalid_metadata")

    skill_type = raw.get("type", "flat")
    if skill_type not in {"router", "procedure", "flat"}:
        return _composition_error("composition_invalid_metadata")
    result = {"type": skill_type, "diagnostics": diagnostics}

    stable_id = raw.get("stable_id")
    if stable_id is not None:
        if not _valid_composition_id(stable_id):
            return _composition_error("composition_invalid_metadata")
        result["stable_id"] = stable_id
    trigger = raw.get("trigger")
    if trigger is not None:
        if not isinstance(trigger, str) or not trigger.strip() or len(trigger) > 240:
            return _composition_error("composition_invalid_metadata")
        result["trigger"] = trigger.strip()

    children = raw.get("children", [])
    if not isinstance(children, list) or len(children) > MAX_COMPOSITION_CHILDREN:
        return _composition_error("composition_invalid_metadata")
    normalized_children = []
    children_by_id = {}
    for child in children:
        if not isinstance(child, dict):
            return _composition_error("composition_invalid_metadata")
        child_id, skill = child.get("id"), child.get("skill")
        child_trigger = child.get("trigger")
        if (
            not _valid_composition_id(child_id)
            or not _valid_composition_id(skill)
            or not isinstance(child_trigger, str)
            or not child_trigger.strip()
            or len(child_trigger) > 240
        ):
            return _composition_error("composition_invalid_metadata")
        normalized = {
            "id": child_id,
            "skill": skill,
            "trigger": child_trigger.strip(),
        }
        prior = children_by_id.get(child_id)
        if prior is not None:
            if prior != normalized:
                return _composition_error("composition_invalid_metadata")
            continue
        children_by_id[child_id] = normalized
        normalized_children.append(normalized)
    if skill_type != "router" and normalized_children:
        return _composition_error("composition_invalid_metadata")
    result["children"] = normalized_children

    invariants = _parse_invariants(raw.get("invariants"))
    overrides = _parse_invariants(raw.get("invariant_overrides"))
    if invariants is None or overrides is None:
        return _composition_error("composition_invalid_metadata")
    result["invariants"] = invariants
    result["invariant_overrides"] = overrides

    depth = raw.get("max_depth")
    if depth is not None:
        if (
            isinstance(depth, bool)
            or not isinstance(depth, int)
            or depth < 0
            or depth > HARD_COMPOSITION_DEPTH
        ):
            return _composition_error("composition_invalid_metadata")
        result["max_depth"] = depth
    content_chars = raw.get("content_chars")
    if content_chars is not None:
        if (
            isinstance(content_chars, bool)
            or not isinstance(content_chars, int)
            or content_chars < 0
            or content_chars > MAX_COMPOSITION_CONTENT_CHARS
        ):
            return _composition_error("composition_invalid_metadata")
        result["content_chars"] = content_chars
    return result


def _keyed_invariants(values: list[str]) -> dict[str, str]:
    keyed = {}
    for value in values:
        if "=" in value:
            key, setting = value.split("=", 1)
            key = key.strip().casefold()
            setting = setting.strip()
            if key:
                keyed[key] = setting
    return keyed


def _merge_invariants(
    inherited: dict[str, list[str]],
    metadata: dict,
    chain: list[str],
) -> dict | None:
    merged = {category: list(inherited[category]) for category in _CATEGORIES}
    for category in _CATEGORIES:
        existing = _keyed_invariants(merged[category])
        for source_name in ("invariants", "invariant_overrides"):
            for value in metadata[source_name][category]:
                if "=" in value:
                    key, setting = value.split("=", 1)
                    normalized_key = key.strip().casefold()
                    setting = setting.strip()
                    if normalized_key in existing and existing[normalized_key] != setting:
                        return _composition_error(
                            "composition_invariant_conflict",
                            category=category,
                            key=normalized_key,
                            values=[existing[normalized_key], setting],
                            chain=chain,
                        )
                    existing[normalized_key] = setting
                if value not in merged[category]:
                    merged[category].append(value)
    return merged


def validate_skill_composition(
    root_id: str,
    *,
    load_metadata: Callable[[str], dict | None],
    selected_children: list[str] | None = None,
    max_depth: int | None = None,
) -> dict:
    """Validate a shallow skill graph and return metadata-only child selection."""
    if not _valid_composition_id(root_id):
        return _composition_error("composition_invalid_metadata")
    if max_depth is not None and (
        isinstance(max_depth, bool)
        or not isinstance(max_depth, int)
        or max_depth < 0
        or max_depth > HARD_COMPOSITION_DEPTH
    ):
        return _composition_error("composition_depth_exceeded")

    loaded: dict[str, dict] = {}
    inherited_by_path: dict[tuple[str, ...], dict[str, list[str]]] = {}
    validated_paths: list[tuple[str, ...]] = []
    diagnostics = []

    def visit(
        skill_id: str,
        depth: int,
        chain: list[str],
        inherited: dict[str, list[str]],
        limit: int,
    ) -> dict | None:
        if skill_id in chain:
            return _composition_error(
                "composition_cycle", chain=[*chain, skill_id]
            )
        if depth > limit:
            return _composition_error(
                "composition_depth_exceeded", chain=[*chain, skill_id]
            )
        if len(validated_paths) >= MAX_COMPOSITION_VISITS:
            return _composition_error(
                "composition_depth_exceeded",
                reason="composition_visit_limit",
                limit=MAX_COMPOSITION_VISITS,
                chain=[*chain, skill_id],
            )
        frontmatter = load_metadata(skill_id)
        if frontmatter is None:
            return _composition_error(
                "composition_missing_child", child=skill_id, chain=[*chain, skill_id]
            )
        metadata = parse_composition_metadata(frontmatter)
        if not metadata.get("success", True):
            return {**metadata, "chain": [*chain, skill_id]}
        local_limit = min(limit, metadata.get("max_depth", limit))
        merged = _merge_invariants(inherited, metadata, [*chain, skill_id])
        if merged is None or not merged.get("success", True):
            return merged
        loaded[skill_id] = metadata
        current_path = tuple([*chain, skill_id])
        inherited_by_path[current_path] = merged
        validated_paths.append(current_path)
        diagnostics.extend(metadata.get("diagnostics", []))
        next_chain = [*chain, skill_id]
        for child in metadata["children"]:
            error = visit(child["skill"], depth + 1, next_chain, merged, local_limit)
            if error:
                return error
        return None

    root_frontmatter = load_metadata(root_id)
    if root_frontmatter is None:
        return _composition_error("composition_missing_child", child=root_id)
    root_preview = parse_composition_metadata(root_frontmatter)
    if not root_preview.get("success", True):
        return root_preview
    limit = max_depth if max_depth is not None else root_preview.get(
        "max_depth", DEFAULT_COMPOSITION_DEPTH
    )
    empty = {category: [] for category in _CATEGORIES}
    error = visit(root_id, 0, [], empty, limit)
    if error:
        return error
    root = loaded[root_id]
    declared = {child["id"]: child for child in root["children"]}
    if selected_children is not None:
        if not isinstance(selected_children, list) or any(
            not isinstance(value, str) for value in selected_children
        ):
            return _composition_error("composition_child_not_declared")
        unknown = list(dict.fromkeys(
            value for value in selected_children if value not in declared
        ))
        if unknown:
            return _composition_error(
                "composition_child_not_declared", children=unknown
            )
        requested = set(selected_children)
    else:
        requested = set()

    def child_payload(child: dict) -> dict:
        metadata = loaded[child["skill"]]
        payload = dict(child)
        if "content_chars" in metadata:
            payload["estimated_chars"] = metadata["content_chars"]
        payload["type"] = metadata["type"]
        payload["inherited_invariants"] = inherited_by_path[(root_id, child["skill"])]
        return payload

    available = [child_payload(child) for child in root["children"]]
    selected = [child for child in available if child["id"] in requested]
    direct_child_chars = sum(child.get("estimated_chars", 0) for child in available)
    selected_child_chars = sum(child.get("estimated_chars", 0) for child in selected)
    graph_chars = sum(
        loaded[path[-1]].get("content_chars", 0) for path in validated_paths
    )
    root_chars = root.get("content_chars", 0)
    return {
        "success": True,
        "root": root_id,
        "type": root["type"],
        "selected_children": selected,
        "available_children": available,
        "inherited_invariants": inherited_by_path[(root_id,)],
        "cost": {
            "root_chars": root_chars,
            "selected_child_chars": selected_child_chars,
            "direct_child_chars": direct_child_chars,
            "validated_graph_chars": graph_chars,
            "validated_nodes": len(validated_paths),
            "max_validated_nodes": MAX_COMPOSITION_VISITS,
        },
        "diagnostics": list(dict.fromkeys(diagnostics)),
        "depth": limit,
    }
