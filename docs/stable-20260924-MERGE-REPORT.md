# Stable upstream integration

Fork base: `8b9a5ebd34c4e771832f9ca57e4b863c107d25d2`.
Upstream: stable `v2026.9.24`, commit `f97608f178d1ffeca59860195ab7da295f7c8e5f` (Hermes 0.21.5).
This is a real two-parent merge; no history rewrite or archive reconstruction.

## Conflict decisions

Thirteen paths conflicted. GPT-6/Codex backports (`47ac95b`, `a50cb32`) overlap upstream removal of unsupported GPT-6 Terra catalog/picker entries. Adopt supported stable catalogs; retain GPT-5.6 Terra and GPT-6 Sol/Luna/Astra. This does not remove a working account route.

Progressive retrieval (`a5fea82`), prominent roots (`4c0f31a`), usage sorting (`2368a96`), and dedup fixes (`063b723`, `b19a81c`, `eaa2174`, plus `df8da70` coverage) overlap skill/plugin/prompt changes. Combine topology with application gating; preserve projection-aware session/task dedup and all compatible tests. Eight test methods omitted by the first candidate were restored before review.

Companion durability (`4d80e3e`) and CI adaptation (`232711d`) overlap dependency metadata. Retain companion PyJWT and jsonschema test tooling; union and deduplicate lock exclusions without fabricating package records.

## Preserved custom features

Curator audits; progressive/composed retrieval and topology; prominent roots; context/session dedup resets; secure companion pairing/durability/proof contracts; dashboard size/call sorting; dependency security fixes; hosted-runner adaptations; contributor provenance.

## Validation gates

Local work used tool-free Codex OAuth patch generation because native sandbox namespaces are blocked. Only isolated-clone file edits were applied. Syntax/JSON/TOML checks and test-name preservation passed; no local package installs, tests or builds ran.

Independent exact-tree review and GitHub CI remain mandatory before deployment. A focused workflow checks both candidate and exact stable parent with locked dependencies and the repository test runner. Full PR CI covers broader regressions/builds. No deployment has occurred.
