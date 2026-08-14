"""Pure normalization and validation for skill hierarchy metadata.

This module deliberately has no filesystem, tool, or configuration dependencies.
Callers provide the complete canonical skill index for graph validation.
"""

from __future__ import annotations

import re
from typing import Any

_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:/-]+$")
_ROLES = frozenset({"leaf", "router", "root"})


def _valid_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(_IDENTIFIER.fullmatch(value))
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def _diagnostic(code: str, **details: Any) -> dict[str, Any]:
    return {"code": code, **details}


def normalize_skill_topology(frontmatter: object) -> dict[str, Any]:
    """Return additive, fail-open normalized hierarchy metadata.

    Invalid values fall back to their documented defaults and remain visible in
    ``diagnostics``. References are validated against the full index separately.
    """
    source = frontmatter if isinstance(frontmatter, dict) else {}
    diagnostics: list[dict[str, Any]] = []

    role = source.get("skill_role", "leaf")
    if not isinstance(role, str) or role not in _ROLES:
        diagnostics.append(_diagnostic("invalid_skill_role", value=role))
        role = "leaf"

    parent = source.get("parent_skill")
    if parent is not None and not _valid_identifier(parent):
        diagnostics.append(_diagnostic("invalid_parent_skill", value=parent))
        parent = None

    children = source.get("child_skills", [])
    normalized_children: list[str] = []
    if not isinstance(children, list):
        diagnostics.append(_diagnostic("invalid_child_skills", value=children))
        children = []
    for child in children:
        if not _valid_identifier(child):
            diagnostics.append(_diagnostic("invalid_child_identifier", value=child))
            continue
        if child not in normalized_children:
            normalized_children.append(child)

    root_eligible = source.get("root_eligible", False)
    if not isinstance(root_eligible, bool):
        diagnostics.append(_diagnostic("invalid_root_eligible", value=root_eligible))
        root_eligible = False

    if role == "root" and not root_eligible:
        diagnostics.append(_diagnostic("root_not_eligible"))
    if role == "leaf" and normalized_children:
        diagnostics.append(_diagnostic("leaf_has_children"))

    return {
        "skill_role": role,
        "parent_skill": parent,
        "child_skills": normalized_children,
        "root_eligible": root_eligible,
        "diagnostics": diagnostics,
    }


def validate_skill_topology(metadata: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Validate normalized metadata against a canonical skill index.

    The result is deterministic and retains one entry for every input skill.
    """
    result = {name: dict(value) for name, value in sorted(metadata.items())}
    known = set(result)

    for name, value in result.items():
        diagnostics = list(value.get("diagnostics", []))
        if not _valid_identifier(name):
            diagnostics.append(_diagnostic("invalid_skill_identifier", value=name))
        parent = value.get("parent_skill")
        children = value.get("child_skills", [])
        if parent == name:
            diagnostics.append(_diagnostic("self_reference", field="parent_skill"))
        elif parent is not None and parent not in known:
            diagnostics.append(_diagnostic("missing_parent", reference=parent))
        for child in children:
            if child == name:
                diagnostics.append(_diagnostic("self_reference", field="child_skills"))
            elif child not in known:
                diagnostics.append(_diagnostic("missing_child", reference=child))
        value["diagnostics"] = diagnostics

    edges: dict[str, list[str]] = {name: [] for name in result}
    for name, value in result.items():
        for child in value.get("child_skills", []):
            if child in known and child not in edges[name]:
                edges[name].append(child)
        parent = value.get("parent_skill")
        if parent in known and name not in edges[parent]:
            edges[parent].append(name)
    state: dict[str, int] = {}
    cycle_nodes: set[str] = set()

    def visit(name: str, path: list[str]) -> None:
        state[name] = 1
        for child in edges[name]:
            if state.get(child) == 1:
                cycle_nodes.update(path[path.index(child) :])
            elif state.get(child, 0) == 0:
                visit(child, [*path, child])
        state[name] = 2

    for name in sorted(result):
        if state.get(name, 0) == 0:
            visit(name, [name])
    for name in sorted(cycle_nodes):
        result[name]["diagnostics"].append(_diagnostic("cycle"))

    return {"skills": result}
