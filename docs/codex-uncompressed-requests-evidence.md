# Codex uncompressed request evidence

## Candidate

- Base commit: `19c32e9ebd0b1633bcef45f410a38077e3276440` on the published `fix/webapp-mcp-https` history; `git cat-file -t` reported `commit`, and work began with `HEAD` exactly at that object.
- Candidate branch: `work`.
- Scope: remove the sync/async outbound Codex zstd event-hook wiring and its dead hook implementation; retain the existing HTTP clients, transports, proxy/pooling behavior, identity/residency headers, request JSON, and response handling.
- No private request data was retrieved, copied, committed, or synthesized. No live-provider test was run; provider verification remains the parent's gate.

## Reproduction and regression proof

The regression test dispatches the same representative JSON through real sync and async `httpx` client request paths into mock transports. It asserts byte-for-byte raw JSON, absence of `Content-Encoding`, and the exact uncompressed `Content-Length`. It has no `compression.zstd` import or version skip.

- RED on base behavior: `HERMES_PYTHON=/tmp/hermes-test-python scripts/run_tests.sh tests/agent/test_codex_request_compression.py` — 2 collected, 2 failed. The sync request reached the transport as zstd bytes instead of JSON. The async row also encountered the temporary mixed-environment `typing_extensions` mismatch after entering the client path.
- GREEN after the fix: the same canonical command — 2 passed, 0 failed.
- Relevant client/header suites: `HERMES_PYTHON=/tmp/hermes-test-python scripts/run_tests.sh tests/agent/test_codex_cloudflare_headers.py tests/agent/test_codex_happy_eyeballs.py tests/agent/test_shared_http_transport.py tests/agent/test_ssl_transport_contracts.py tests/agent/test_auxiliary_client_ssl_verify.py tests/agent/test_create_openai_client_ssl_verify.py` — 6 files, 34 passed, 0 failed.

`/tmp/hermes-test-python` used the checkout `.venv` dependencies and exposed the host pytest installation because the checkout environment lacked pytest. The first plain canonical invocation attempted to provision pinned uv 0.13.5 and stopped when both configured download URLs returned HTTP 403; it collected no tests.

## Lint and review

- `ruff check agent/codex_headers.py agent/process_bootstrap.py tests/agent/test_codex_request_compression.py` — passed with the installed ruff 0.15.12 preview-selection warnings.
- `ruff format --check agent/codex_headers.py agent/process_bootstrap.py tests/agent/test_codex_request_compression.py` — reported all three files would be reformatted by installed ruff 0.15.12; no formatting rewrite was applied with the wrong pinned version.
- `python scripts/check` — not run to completion: the repository requires ruff 0.15.22, while the environment has 0.15.12 and no usable `uv`/`uvx` path for the pinned tool.
- `git diff --check` — passed.
- Self-review: one thin behavior change only; no retry, configuration, auth, reasoning/history, response-compression, proxy, pool, or transport changes. The two dispatch modes cover the removed sync and async wiring. No repair round was needed after GREEN.

## Known unverified gates

- Full `scripts/run_tests.sh` suite.
- Pinned `python scripts/check` lint/format suite.
- Other supported Python/OS CI jobs.
- Live ChatGPT/Codex provider behavior (intentionally not claimed or attempted).
