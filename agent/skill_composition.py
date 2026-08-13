"""Deterministic, bounded Markdown skill-section retrieval.

Sections include their heading-level subtree. Safety support is limited to
ancestor safety, preceding same-parent safety, and document-global safety
before the first operational sibling.
"""
from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass

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
