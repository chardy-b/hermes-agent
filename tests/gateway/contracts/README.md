# Companion API contract provenance

`companion-v1.openapi.yaml` is a byte-for-byte pinned test artifact from the
WIL-46 Android companion contract. It is committed here so a standard Hermes
Agent checkout and CI job can run contract verification without a sibling
worktree or network access.

- Upstream repository: `Chardy-b/hermes-android-companion`
- Upstream path: `contracts/companion-v1.openapi.yaml`
- Merged WIL-46 commit: `173b2c7879679543ee4349db1fcffbd60a3f12ee`
- Reviewed WIL-46 head available locally: `c7bc7f2fbc29d3aff38f3ddc1375acc8682e4f84`
- Contract-introducing commit: `4b79166c99324f4987d1737276e81ea624cd8bef`
- Upstream Git blob: `98d2716a5b026a6b2070a5c9b4c639756517a656`
- Artifact SHA-256: `040a4c215c09c15010e8e554203ba5f2b2b5e86761fb9a3e3aec197a1fa88c38`

`tests.gateway.companion_contract.CompanionContract` verifies the SHA-256
before loading the document, then validates real aiohttp requests and
responses by OpenAPI operation, status, media type, parameters, and JSON
Schema.

WIL-47 has two deliberate backend-only deltas from this pinned WIL-46 source:
operator-scoped chat-session listing and operator session revocation. The test
adapter declares those deltas explicitly in `_WIL47_SECURITY_OVERRIDES` and
`_WIL47_OPERATIONS`; it does not present them as upstream WIL-46 definitions.
If either delta gains a normative cross-repository contract, replace the local
overlay with that pinned artifact and record its exact provenance here.

To update the artifact, copy it from a reviewed upstream commit, update the
blob and SHA-256 values in this file and `companion_contract.py`, and rerun the
focused contract test. Do not add a runtime/network fetch.
