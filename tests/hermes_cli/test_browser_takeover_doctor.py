"""Doctor readiness coverage for opt-in browser takeover."""

from types import SimpleNamespace

from gateway.config import Platform
from hermes_cli.browser_takeover_doctor import (
    _npm_global_roots,
    _probe_loopback_endpoint,
    collect_browser_takeover_readiness,
    evaluate_browser_takeover_readiness,
)


def _config(**overrides):
    value = {
        "enabled": True,
        "adapter": "camofox-vnc",
        "public_origin": "https://takeover.example",
    }
    value.update(overrides)
    return value


def test_ready_configuration_reports_every_takeover_boundary_without_urls():
    rows = evaluate_browser_takeover_readiness(
        _config(),
        listener_host="127.0.0.1",
        camofox_url="http://127.0.0.1:9377",
        viewer_url="http://127.0.0.1:6080",
        adapter_healthy=True,
        viewer_reachable=True,
        node_available=True,
        package_installed=True,
    )
    assert {row.label for row in rows} == {
        "Browser takeover adapter health",
        "Browser/display continuity",
        "Private browser endpoint",
        "Private VNC/noVNC endpoint",
        "Public listener exposure",
        "Takeover base URL",
        "Takeover TLS",
        "Node.js dependency",
        "Camofox package dependency",
    }
    assert all(row.ok for row in rows)
    rendered = repr(rows)
    assert "9377" not in rendered
    assert "6080" not in rendered


def test_exposed_listener_and_remote_private_transports_fail_closed():
    rows = evaluate_browser_takeover_readiness(
        _config(public_origin="http://takeover.example/path"),
        listener_host="localhost",
        camofox_url="http://10.0.0.8:9377",
        viewer_url="ws://10.0.0.8:6080",
        adapter_healthy=True,
        viewer_reachable=False,
        node_available=False,
        package_installed=False,
    )
    failed = {row.label for row in rows if not row.ok}
    assert failed == {
        "Browser/display continuity",
        "Private browser endpoint",
        "Private VNC/noVNC endpoint",
        "Public listener exposure",
        "Takeover base URL",
        "Takeover TLS",
        "Node.js dependency",
        "Camofox package dependency",
    }


def test_disabled_takeover_adds_no_optional_doctor_noise():
    assert (
        evaluate_browser_takeover_readiness(
            {"enabled": False},
            listener_host="0.0.0.0",
            camofox_url="",
            viewer_url="",
            adapter_healthy=False,
            viewer_reachable=False,
            node_available=False,
            package_installed=False,
        )
        == []
    )


def test_npm_package_roots_are_resolved_without_a_shell(monkeypatch, tmp_path):
    import subprocess
    from pathlib import Path

    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command, 0, "/opt/npm/lib/node_modules\n", ""
        )

    monkeypatch.setattr("subprocess.run", fake_run)

    roots = _npm_global_roots("/usr/bin/npm", tmp_path / "node")

    assert roots == (Path("/opt/npm/lib/node_modules"),)
    assert all(isinstance(command, list) for command, _ in calls)
    assert all(kwargs["timeout"] == 5 for _, kwargs in calls)


def test_viewer_probe_is_network_bounded_to_literal_loopback(monkeypatch):
    opened = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(
        "socket.create_connection",
        lambda address, timeout: opened.append((address, timeout)) or Connection(),
    )

    assert _probe_loopback_endpoint("http://127.0.0.1:6080")
    assert not _probe_loopback_endpoint("http://10.0.0.8:6080")
    assert opened == [(("127.0.0.1", 6080), 2.0)]


def test_live_collector_reads_api_platform_and_provider_health(monkeypatch, tmp_path):
    from gateway import config as gateway_config
    from hermes_cli import config as hermes_config
    from tools import browser_camofox

    package = (
        tmp_path
        / "node"
        / "lib"
        / "node_modules"
        / "@askjo"
        / "camofox-browser"
        / "package.json"
    )
    package.parent.mkdir(parents=True)
    package.write_text('{"version":"1.5.2"}', encoding="utf-8")
    platform = SimpleNamespace(
        extra={
            "host": "127.0.0.1",
            "browser_takeover": _config(),
        }
    )
    monkeypatch.setattr(
        gateway_config,
        "load_gateway_config",
        lambda: SimpleNamespace(platforms={Platform.API_SERVER: platform}),
    )
    monkeypatch.setattr(hermes_config, "get_hermes_home", lambda: str(tmp_path))
    monkeypatch.setattr(
        browser_camofox, "get_camofox_url", lambda: "http://127.0.0.1:9377"
    )
    monkeypatch.setattr(
        "hermes_cli.browser_takeover_doctor._probe_loopback_endpoint",
        lambda _url: True,
    )
    monkeypatch.setattr(browser_camofox, "get_vnc_url", lambda: "http://127.0.0.1:6080")
    monkeypatch.setattr(browser_camofox, "check_camofox_available", lambda: True)
    monkeypatch.setattr("shutil.which", lambda command: "/usr/bin/node")

    rows = collect_browser_takeover_readiness()

    assert rows
    assert all(row.ok for row in rows)


def test_live_collector_never_contacts_non_loopback_provider(monkeypatch, tmp_path):
    from gateway import config as gateway_config
    from hermes_cli import config as hermes_config
    from tools import browser_camofox

    platform = SimpleNamespace(
        extra={"host": "127.0.0.1", "browser_takeover": _config()}
    )
    monkeypatch.setattr(
        gateway_config,
        "load_gateway_config",
        lambda: SimpleNamespace(platforms={Platform.API_SERVER: platform}),
    )
    monkeypatch.setattr(hermes_config, "get_hermes_home", lambda: str(tmp_path))
    monkeypatch.setattr(
        browser_camofox, "get_camofox_url", lambda: "https://remote.example"
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("non-loopback provider must not be contacted")

    monkeypatch.setattr(browser_camofox, "check_camofox_available", forbidden)
    monkeypatch.setattr(browser_camofox, "get_vnc_url", forbidden)
    monkeypatch.setattr(
        "hermes_cli.browser_takeover_doctor._probe_loopback_endpoint", forbidden
    )
    monkeypatch.setattr("shutil.which", lambda _command: None)

    rows = collect_browser_takeover_readiness()

    by_label = {row.label: row for row in rows}
    assert not by_label["Private browser endpoint"].ok
    assert not by_label["Browser takeover adapter health"].ok
