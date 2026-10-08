# Stable upstream integration

Fork base: `8b9a5ebd34c4e771832f9ca57e4b863c107d25d2`.
Upstream: stable `v2026.9.24`, commit `f97608f178d1ffeca59860195ab7da295f7c8e5f` (Hermes 0.21.5).
This report describes the existing two-parent integration; the short commit IDs below are
source commits referenced by the conflict decisions, not new commits created by validation.

## Conflict decisions

Thirteen paths conflicted. GPT-6/Codex backports (`47ac95b`, `a50cb32`) overlap upstream removal of unsupported GPT-6 Terra catalog/picker entries. Adopt supported stable catalogs; retain GPT-5.6 Terra and GPT-6 Sol/Luna/Astra. This does not remove a working account route.

Progressive retrieval (`a5fea82`), prominent roots (`4c0f31a`), usage sorting (`2368a96`), and dedup fixes (`063b723`, `b19a81c`, `eaa2174`, plus `df8da70` coverage) overlap skill/plugin/prompt changes. Combine topology with application gating; preserve projection-aware session/task dedup and all compatible tests. Eight test methods omitted by the first candidate were restored before review.

Companion durability (`4d80e3e`) and CI adaptation (`232711d`) overlap dependency metadata. Retain companion PyJWT and jsonschema test tooling. The canonical `uv.lock` is the generated artifact verified by GitHub Actions run `37712275782`; it is already integrated and was not edited here.

## Preserved custom features

Curator audits; progressive/composed retrieval and topology; prominent roots; context/session dedup resets; secure companion pairing/durability/proof contracts; dashboard size/call sorting; dependency security fixes; hosted-runner adaptations; contributor provenance.

## Validation gates

The stale review scratch output was removed. The focused repository test runner could not start because this checkout has no virtualenv with pytest; Python syntax compilation and JSON parsing passed. No package installs, builds, direct credential handling, pushes, or commits were used during validation. Lock consistency on this exact tree, the full suite, and PR CI remain pending; no test or broader CI result is being claimed.

Independent exact-tree review and GitHub CI remain mandatory before deployment. A focused workflow checks both candidate and exact stable parent with locked dependencies and the repository test runner. Full PR CI covers broader regressions/builds. No deployment has occurred.

## Lock provenance

The canonical `uv.lock` was produced by GitHub Actions run `#37712275782` on branch `maintenance/stable-20260924-lock` using `uv 0.12.13` and the merged `pyproject.toml`. Artifact `stable-canonical-lock` (ID 11522177676, SHA-256 `67064640...b9ebf84`) was retrieved through the Keyholder credential broker's github-readonly grant, verified against its published digest, and matched the candidate manifest byte-for-byte. Transitive packages `aiohttp`/`aiohttp-retry`/`pydantic`/`python-dateutil`/`typing-extensions`/`urllib3` for `hindsight-client` are present. Blob OID: `6096bca6d5396e19be3fdef68eb07648d83323af`. This provenance does not replace pending lock validation and CI on the exact tree.
