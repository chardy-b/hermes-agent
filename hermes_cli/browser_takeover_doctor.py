"""Content-free readiness checks for opt-in browser takeover."""

from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit

_CAMOFOX_VERSION = "1.5.2"


@dataclass(frozen=True)
class TakeoverReadinessRow:
    label: str
    ok: bool
    detail: str


def _loopback_endpoint(value: str) -> bool:
    try:
        parsed = urlsplit(str(value or ""))
        host = parsed.hostname or ""
        return (
            parsed.scheme in {"http", "https", "ws", "wss"}
            and not parsed.username
            and not parsed.password
            and ipaddress.ip_address(host).is_loopback
        )
    except ValueError:
        return False


def _origin_shape(value: str) -> bool:
    try:
        parsed = urlsplit(str(value or ""))
        return bool(
            parsed.scheme in {"http", "https"}
            and parsed.netloc
            and not parsed.username
            and not parsed.password
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


def _https_origin(value: str) -> bool:
    try:
        parsed = urlsplit(str(value or ""))
        return _origin_shape(value) and parsed.scheme == "https"
    except ValueError:
        return False


def _loopback_host(value: str) -> bool:
    try:
        return ipaddress.ip_address(str(value or "")).is_loopback
    except ValueError:
        return False


def _probe_loopback_endpoint(value: str, *, timeout: float = 2.0) -> bool:
    """Probe only a literal-loopback TCP endpoint; never follow URLs."""
    if not _loopback_endpoint(value):
        return False
    parsed = urlsplit(str(value or ""))
    port = parsed.port or (443 if parsed.scheme in {"https", "wss"} else 80)
    try:
        with socket.create_connection((parsed.hostname or "", port), timeout=timeout):
            return True
    except OSError:
        return False


def _npm_global_roots(npm_bin: str, node_root: Path) -> tuple[Path, ...]:
    roots: list[Path] = []
    for command in (
        [npm_bin, "root", "--global", "--prefix", str(node_root)],
        [npm_bin, "root", "--global"],
    ):
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        root = Path(result.stdout.strip())
        if result.returncode == 0 and root.is_absolute() and root not in roots:
            roots.append(root)
    return tuple(roots)


def _approved_camofox_installed(package_files: Sequence[Path]) -> bool:
    for package_file in package_files:
        try:
            payload = json.loads(package_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if payload.get("version") == _CAMOFOX_VERSION:
            return True
    return False


def evaluate_browser_takeover_readiness(
    takeover_config: dict[str, Any],
    *,
    listener_host: str,
    camofox_url: str,
    viewer_url: str,
    adapter_healthy: bool,
    viewer_reachable: bool,
    node_available: bool,
    package_installed: bool,
) -> list[TakeoverReadinessRow]:
    """Return bounded diagnostics without echoing endpoints or secrets."""
    if not bool(takeover_config.get("enabled", False)):
        return []

    adapter_selected = (
        str(takeover_config.get("adapter") or "").strip().casefold() == "camofox-vnc"
    )
    browser_private = _loopback_endpoint(camofox_url)
    viewer_private = _loopback_endpoint(viewer_url)
    adapter_ok = adapter_selected and adapter_healthy
    continuity_ok = (
        adapter_ok and browser_private and viewer_private and viewer_reachable
    )
    public_origin = str(takeover_config.get("public_origin") or "")

    return [
        TakeoverReadinessRow(
            "Browser takeover adapter health",
            adapter_ok,
            "configured and healthy" if adapter_ok else "unavailable or unsupported",
        ),
        TakeoverReadinessRow(
            "Browser/display continuity",
            continuity_ok,
            "private browser and viewer are reachable"
            if continuity_ok
            else "private browser/display check failed",
        ),
        TakeoverReadinessRow(
            "Private browser endpoint",
            browser_private,
            "literal loopback endpoint"
            if browser_private
            else "missing or not literal loopback",
        ),
        TakeoverReadinessRow(
            "Private VNC/noVNC endpoint",
            viewer_private and viewer_reachable,
            "loopback viewer endpoint reachable"
            if viewer_private and viewer_reachable
            else "viewer endpoint is not reachable on loopback",
        ),
        TakeoverReadinessRow(
            "Public listener exposure",
            _loopback_host(listener_host),
            "loopback-only"
            if _loopback_host(listener_host)
            else "must bind to literal loopback",
        ),
        TakeoverReadinessRow(
            "Takeover base URL",
            _origin_shape(public_origin),
            "exact origin configured"
            if _origin_shape(public_origin)
            else "must be one origin without credentials or path",
        ),
        TakeoverReadinessRow(
            "Takeover TLS",
            _https_origin(public_origin),
            "HTTPS required and configured"
            if _https_origin(public_origin)
            else "HTTPS origin required",
        ),
        TakeoverReadinessRow(
            "Node.js dependency",
            node_available,
            "available" if node_available else "run installer dependency repair",
        ),
        TakeoverReadinessRow(
            "Camofox package dependency",
            package_installed,
            "installed"
            if package_installed
            else "run scripts/install.sh --ensure browser-takeover",
        ),
    ]


def collect_browser_takeover_readiness() -> list[TakeoverReadinessRow]:
    """Inspect the live opt-in configuration without returning sensitive values."""
    import shutil

    from gateway.config import Platform, load_gateway_config
    from hermes_cli.config import get_hermes_home
    from tools import browser_camofox

    gateway = load_gateway_config()
    platform = gateway.platforms.get(Platform.API_SERVER)
    if platform is None:
        return []
    extra = platform.extra or {}
    takeover = extra.get("browser_takeover")
    if not isinstance(takeover, dict):
        return []

    node_root = Path(get_hermes_home()) / "node"
    npm_bin = shutil.which("npm")
    hermes_npm = node_root / "bin" / "npm"
    if npm_bin is None and hermes_npm.is_file():
        npm_bin = str(hermes_npm)
    roots = list(_npm_global_roots(npm_bin, node_root)) if npm_bin else []
    roots.extend((node_root / "lib" / "node_modules", node_root / "node_modules"))
    package_files = tuple(
        root / "@askjo" / "camofox-browser" / "package.json" for root in roots
    )
    node_available = (
        shutil.which("node") is not None or (node_root / "bin" / "node").is_file()
    )
    camofox_url = browser_camofox.get_camofox_url()
    browser_private = _loopback_endpoint(camofox_url)
    adapter_healthy = bool(
        browser_private and browser_camofox.check_camofox_available()
    )
    vnc_url = (browser_camofox.get_vnc_url() or "") if adapter_healthy else ""
    viewer_reachable = bool(vnc_url and _probe_loopback_endpoint(vnc_url))
    return evaluate_browser_takeover_readiness(
        takeover,
        listener_host=str(extra.get("host") or "127.0.0.1"),
        camofox_url=camofox_url,
        viewer_url=vnc_url,
        adapter_healthy=adapter_healthy,
        viewer_reachable=viewer_reachable,
        node_available=node_available,
        package_installed=_approved_camofox_installed(package_files),
    )
