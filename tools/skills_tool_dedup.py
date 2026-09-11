"""Session-scoped, projection-aware skill content identity and repeat-view dedup.
Cleared on compression so summarized-away skill content is served again.
"""

import copy
import hashlib
import json
import os
import threading
from typing import Dict

_skill_view_tracker: Dict[str, Dict[str, dict]] = {}
_skill_view_scope_tasks: Dict[str, set[str]] = {}
_skill_view_tracker_lock = threading.Lock()
_SKILL_VIEW_DEDUP_CAP = 200
_SKILL_VIEW_SCOPE_ALIAS_CAP = 200
_SKILL_VIEW_DEDUP_MESSAGE = (
    "Skill content unchanged since it was loaded earlier in this conversation — "
    "refer to the earlier skill_view result; it is still current and complete."
)


def _skill_view_identity(args, payload):
    name = str(payload.get("name") or args.get("name") or "")
    source_path = payload.get("_source_path")
    source_identity = (
        hashlib.sha256(
            os.path.realpath(str(source_path)).encode("utf-8")
        ).hexdigest()
        if source_path
        else None
    )
    max_chars = args.get("max_chars")
    progressive = bool(payload.get("projection")) or any(
        key in args for key in ("heading", "query", "max_chars", "children")
    )
    if progressive and max_chars is None:
        max_chars = 8000
    children = args.get("children", "__omitted__")
    if children != "__omitted__":
        children = None if children is None else sorted(set(children))
    retrieval = {
        "name": name,
        "source_identity": source_identity,
        "file_path": args.get("file_path"),
                 "heading": args.get("heading"), "query": args.get("query"),
                 "max_chars": max_chars, "children": children}
    rid = hashlib.sha256(json.dumps(retrieval, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    visible = copy.deepcopy(payload)
    visible.pop("_source_path", None)
    visible.pop("content_hash", None)
    visible.pop("retrieval_id", None)
    chash = hashlib.sha256(json.dumps(visible, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return rid, chash, retrieval


def _skill_view_scope(task_id, session_id):
    return "session:" + str(session_id) if session_id else ("task:" + str(task_id) if task_id else None)


def _associate_skill_view_scope(task_id, scope):
    if not task_id or not scope:
        return
    task_key = str(task_id)
    scopes = _skill_view_scope_tasks.setdefault(task_key, set())
    scopes.add(scope)
    while len(_skill_view_scope_tasks) > _SKILL_VIEW_SCOPE_ALIAS_CAP:
        oldest_task = next(iter(_skill_view_scope_tasks))
        if oldest_task == task_key and len(_skill_view_scope_tasks) == 1:
            break
        evicted_scopes = _skill_view_scope_tasks.pop(oldest_task, set())
        for evicted_scope in evicted_scopes:
            _skill_view_tracker.pop(evicted_scope, None)
            for aliases in _skill_view_scope_tasks.values():
                aliases.discard(evicted_scope)


def reset_skill_view_dedup(task_id: str | None = None) -> None:
    with _skill_view_tracker_lock:
        if task_id is None:
            _skill_view_tracker.clear(); _skill_view_scope_tasks.clear()
        else:
            task_key = str(task_id)
            scopes = _skill_view_scope_tasks.pop(task_key, set()) | {
                "task:" + task_key
            }
            for scope in scopes:
                _skill_view_tracker.pop(scope, None)
            for aliases in _skill_view_scope_tasks.values():
                aliases.difference_update(scopes)


def _skill_view_check_or_record(
    scope,
    task_id,
    retrieval_id,
    content_hash,
    payload,
    retrieval,
):
    if not scope:
        return None
    with _skill_view_tracker_lock:
        _associate_skill_view_scope(task_id, scope)
        cache = _skill_view_tracker.setdefault(scope, {})
        prior = cache.get(retrieval_id)
        if prior and prior["content_hash"] == content_hash:
            return json.dumps(
                {
                    "success": True,
                    "status": "unchanged",
                    "name": payload.get("name"),
                    "file": payload.get("file", "SKILL.md"),
                    "dedup": True,
                    "content_returned": False,
                    "content_hash": content_hash,
                    "retrieval_id": retrieval_id,
                    "projection_identity": retrieval,
                    "message": _SKILL_VIEW_DEDUP_MESSAGE,
                },
                ensure_ascii=False,
            )
        cache[retrieval_id] = {
            "content_hash": content_hash,
            "retrieval": retrieval,
        }
        while len(cache) > _SKILL_VIEW_DEDUP_CAP:
            cache.pop(next(iter(cache)))
    return None
