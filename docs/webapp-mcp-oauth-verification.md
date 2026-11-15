# Browser-hosted Desktop MCP OAuth verification receipt

## Scope and authority

- Base: `be9d27d003b041ebd40963dabf2d7b3a193cae0e` (`upgrade/stable-v0.23.0`).
- Isolated branch: `fix/webapp-mcp-https`; preceding unverified candidate: `1e7390e811929527873f854a92f9c23afea70219`.
- Richard explicitly approved **“Yes—use the VPS with resource limits”** for isolated repair, tests and build, with the live app unchanged until verification passes. This supersedes the earlier Cloud-only venue restriction for this task, not for other work.
- Changed files: the MCP OAuth helper, its colocated test, and this receipt. No dependency/lock changes, provider authentication, push, PR, deployment, service control, or live configuration/token writes.

## Repair

Browser-hosted Desktop uses existing dashboard REST start/poll/delete endpoints, captures the original connection/profile, reserves its popup synchronously, clears its opener and applies no-referrer policy before navigation. It preserves the backend's authorization URL (including its HTTPS callback) rather than starting the native gateway loopback callback flow. Native OAuth implementation remains unchanged.

Removed `popup.closed` as a completion signal: COOP can sever the WindowProxy while the real provider tab remains open. Completion now depends on backend flow status, explicit cancellation/profile-change callback, or timeout. A popup close exception cannot prevent DELETE cleanup of the original profile flow or replace the original cancellation error.

## Execution environment

- Reused existing managed Node **26.12.1** and npm **12.0.2**, read-only, under `/mnt/HC_Volume_106820083/hermes-data/default/large-root-migrated/tools/`.
- Copied previously prepared Webapp dependencies into the isolated worktree's private `.build/webapp-workspace`; copied nested renderer dependencies for tests. No package install/prune was run against the live checkout or shared cache.
- Every test/check/build runs in a systemd user scope with `MemoryMax=1200M`, `MemorySwapMax=1800M`, `CPUQuota=100%`; Vitest uses one worker and no file parallelism. Test heap is 768 MiB. Typecheck was also attempted at a 1200 MiB heap with the same cgroup caps.
- HOME, Hermes home/runtime, temporary files and npm/XDG caches are isolated on bulk storage. All commands, environments, exit statuses and logs are retained under `/mnt/HC_Volume_106820083/artifacts/hermes-agent/webapp-mcp-https/local-verification/`.

## Observed results

Commands below run from `apps/desktop` using the managed runtime and the resource scope above. Full argv are saved in each corresponding JSON record.

| Gate | Result |
| --- | --- |
| `npm run test -- --project ui --maxWorkers=1 --no-file-parallelism src/lib/mcp-dashboard-oauth.test.ts` | **11 passed**, including all 4 existing native cases and 7 browser cases. |
| Base-red: same test overlaid on disposable `git archive` of exact published base | **7 browser failed, 4 native passed**. One additional unhandled rejection was emitted by the missing-browser-path failure. |
| Pre-repair red: helper from `1e7390e…`, `-t 'COOP\|cleanup throws'` | **2 failed, 9 skipped**: false window-closed rejection and cleanup SecurityError replacing cancellation. |
| Scoped ESLint for both changed TS files | Passed; formatting-only warnings corrected with scoped `--fix`. |
| `node scripts/build-webapp.mjs --no-install` (the implementation behind `npm run build:webapp`) | **Passed**, reused dependency receipt and built `apps/desktop/dist-webapp/index.html` plus `hermes-build.json`. |
| `tsc -p . --noEmit` | **BLOCKED**: V8 heap exhaustion at both 768 and 1200 MiB; no successful renderer typecheck. |
| Same renderer typecheck on disposable published-base source, with test overlay only | **Same heap exhaustion at 1200 MiB**, exit SIGABRT. This establishes an environmental baseline limitation, not a typecheck waiver. |
| `git diff --check` | Passed. |

The initial Vitest attempt lacked nested `@rolldown/plugin-babel`; copying the already-installed nested dependencies resolved it. Invoking the builder through `npm run` added npm configuration that changed the dependency-reuse key; the direct, unmodified build script with `--no-install` reused the existing verified preparation receipt. No receipt was forged or edited. Build output reports existing ineffective dynamic-import warnings.

## Artifact and remaining release gate

The generated bundle is at the isolated checkout's `apps/desktop/dist-webapp/`, with the standard `hermes-build.json` source/output-hash receipt. A retained archive, per-file checksums and provenance are placed in the local-verification artifact directory. Final test/lint/build reruns use the `final-*` logs there.

**Not declared release-ready:** renderer/full Desktop typecheck remains blocked by the bounded memory budget, on candidate and base. Do not expand the repair or relax the host-protection limits without a new venue decision. Parent should arrange the single security review and resolve this verification gate before deployment.

Tests exercise the actual helper with simulated WindowProxy/REST responses, including an HTTPS callback URL, original-profile cleanup, blocked popups and unsafe URL rejection. They do not prove real provider consent, HTTPS callback transport/server integration, or browser COOP behavior end to end. No real OAuth flow was initiated, and the live app and unknown live `error.log` were left untouched.
