"""Operator documentation contract for secure browser takeover."""

from pathlib import Path


DOC = Path(__file__).parents[1] / "docs" / "browser-human-takeover.md"


def test_operator_guide_documents_security_and_rollback_boundaries():
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "## Threat model and invariants",
        "scripts/install.sh --ensure browser-takeover",
        "host: 127.0.0.1",
        "extra:",
        "managed_persistence: true",
        "public_origin: https://",
        "Tailscale Serve",
        "authenticated reverse proxy",
        "reply exactly `Done`",
        "reply exactly `Cancel`",
        "## Disable and roll back",
        "## Validation boundary",
    ):
        assert required in text
    assert "Do not publish the Camofox, VNC, noVNC, or CDP ports" in text
    assert "Do not claim that gate from mocked health checks" in text
