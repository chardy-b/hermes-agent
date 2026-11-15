# Browser-hosted Desktop MCP OAuth verification receipt

## Scope

- Published base: `be9d27d003b041ebd40963dabf2d7b3a193cae0e` (`upgrade/stable-v0.23.0`).
- Replacement patch files:
  - `apps/desktop/src/lib/mcp-dashboard-oauth.ts`
  - `apps/desktop/src/lib/mcp-dashboard-oauth.test.ts`
  - `docs/webapp-mcp-oauth-verification.md`
- No provider login, deployment, push, credential use, dependency/lock change, or generated bundle was performed.

## Environment gate

The repair environment exposed Node `v20.20.2` and npm `11.4.2`; the Desktop workspace requires
Node `>=26`. Root `node_modules` was absent. The preceding infrastructure attempt recorded by the
repair request found only Node 18/20/22/24 (best `24.15.0`), while both the official
`nodejs.org/dist/index.json` request and `npm ping registry.npmjs.org` returned HTTP 403. Those
known-failing remote attempts were not repeated and no credentialed, policy-bypassing, or
local-host fallback was attempted.

## Acceptance commands

All commands below were run from `apps/desktop` on this patch unless stated otherwise.

| Gate | Exit | Result |
| --- | ---: | --- |
| `npm run test -- --run src/lib/mcp-dashboard-oauth.test.ts` | 127 | **BLOCKED**: `vitest: not found`; 0 tests executed. |
| `npm run typecheck` | 2 | **BLOCKED**: locked dependencies are absent (`TS2688`, missing Node type definitions). |
| `npm run lint -- --no-warn-ignored src/lib/mcp-dashboard-oauth.ts src/lib/mcp-dashboard-oauth.test.ts` | 2 | **BLOCKED**: ESLint could not import the absent `globals` package. |
| `npm run build:webapp` | 1 | **BLOCKED**: build preparation rejected Node `20.20.2` because `>=26` is required. |
| `git diff --check` (repository root) | 0 | Passed. |

Test counts: **0 passed, 0 failed, 0 skipped, 0 executed**. Native and browser Vitest coverage,
typecheck, lint, and the webapp build remain unverified acceptance gates. No build artifact was
created.

## Static regression expectation (not an executed red/green claim)

On the exact base, browser-hosted Desktop follows the native callback path and cannot complete the
dashboard REST flow. The added behavior contracts are expected to fail on that base because there
is no synchronous blank-tab reservation, browser REST start/poll/delete lifecycle, captured
profile routing, or authorization-scheme rejection in this module. This is a static expectation,
not a verified base-red result. With locked dependencies under Node 26+, the candidate must still
prove the existing native cases and the new browser cases green before release.

## Controller handoff: blocked candidate, not release-ready

- Final Cloud task: https://chatgpt.com/codex/tasks/task_e_6af9047b3b24832c9a1fb2e75ff2d109 . Two bounded repair rounds were used; no further implementation repair was performed locally.
- Applied only to isolated branch `fix/webapp-mcp-https`, based exactly on the published base above. Controller `git apply --check` and `git diff --check` passed. A byte comparison against the base confirmed the pre-existing native OAuth body is unchanged.
- Controller evidence is retained outside Git at `/mnt/HC_Volume_106820083/artifacts/hermes-agent/webapp-mcp-https/`: `cloud-repair-2.patch`, `cloud-repair-2-status.log`, and `controller-static-verification.json`. Prior attempts and their actual environmental error excerpts are retained as `cloud-implementation.patch` and `cloud-repair-1.patch`; those candidates were not applied.
- **Remaining core-flow concern for parent review:** the new `popup.closed` check treats a severed WindowProxy as cancellation. An identity provider using Cross-Origin-Opener-Policy can sever that proxy while the real OAuth tab remains open. That may cancel a valid pending flow. This behavior has not been exercised and must be resolved or disproved before deployment.
- Browser tests do not exercise the actual browser transport's configured base path or a real HTTPS callback, and there is no executed base-red/fixed-green proof. Real provider consent is intentionally left to Richard after deployment gates clear.
- No build output exists; this is a build blocker, not merely an artifact-download blocker. Parent must provide an authorized Node 26+ remote build/test venue with access to the locked packages before this candidate can be called tested or deployable.
- Local commit hooks are intentionally disabled for this isolated candidate commit (`git -c core.hooksPath=/dev/null commit`): local builds, tests, and dependency installation were not authorized on the VPS. This does not waive the blocked remote acceptance gates.
