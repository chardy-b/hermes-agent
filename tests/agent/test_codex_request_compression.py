"""Regression coverage for uncompressed outbound Codex request bodies."""

import asyncio
import json

import httpx
import pytest

from agent.process_bootstrap import build_keepalive_http_client, close_shared_transports

OFFICIAL = "https://chatgpt.com/backend-api/codex"


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_codex_responses_dispatches_raw_json(monkeypatch, async_mode):
    payload = {"model": "gpt-6.1-sol", "input": [{"role": "user", "content": "hi " * 500}]}
    expected = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    seen = []

    def respond(request):
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    async def respond_async(request):
        return respond(request)

    close_shared_transports()
    if async_mode:
        monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **kwargs: httpx.MockTransport(respond_async))
    else:
        monkeypatch.setattr(httpx, "HTTPTransport", lambda **kwargs: httpx.MockTransport(respond))
    client = build_keepalive_http_client(OFFICIAL, async_mode=async_mode)

    if async_mode:
        async def send():
            try:
                await client.post(f"{OFFICIAL}/responses", json=payload)
            finally:
                await client.aclose()

        asyncio.run(send())
    else:
        try:
            client.post(f"{OFFICIAL}/responses", json=payload)
        finally:
            client.close()

    assert len(seen) == 1
    request = seen[0]
    assert request.content == expected
    assert "Content-Encoding" not in request.headers
    assert request.headers["Content-Length"] == str(len(expected))
