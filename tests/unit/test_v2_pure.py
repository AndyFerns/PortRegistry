"""Pure/unit tests for v0.2 modules: labels, ignore rules, TOML writer, config,
project detection, alerts delivery, autostart backends and the tray controller."""

from __future__ import annotations

import hashlib
import hmac
import json
import tomllib
from pathlib import Path

import httpx
import pytest

from portregistry.config import WebhookConfig, parse_config
from portregistry.core.ignore import IgnoreRuleView, ephemeral_range, first_match, is_ephemeral
from portregistry.core.tomlwriter import dumps
from portregistry.core.well_known import category_for, label_for, table_size
from portregistry.daemon import alerts as alerts_mod
from portregistry.daemon import autostart
from portregistry.discovery.project import ProjectDetector
from portregistry.exceptions import ConfigError, DaemonNotRunningError
from portregistry.paths import AppPaths
from portregistry.tray.app import TrayController, alert_text, state_from_status


@pytest.fixture
def paths(tmp_path):
    return AppPaths(tmp_path / "c", tmp_path / "d", tmp_path / "l")


# ----------------------------------------------------------------- labels


def test_well_known_labels():
    assert label_for(5432, "tcp") == "PostgreSQL"
    assert label_for(53, "udp") == "DNS"
    assert label_for(443, "udp") == "HTTP/3 (QUIC)"
    assert label_for(443, "tcp") == "HTTPS"
    assert label_for(5432) == "PostgreSQL"
    assert label_for(1) is None
    assert category_for(6379, "tcp") == "cache"
    assert table_size() >= 140


# ----------------------------------------------------------------- ignore


def test_ignore_rule_matching():
    rule = IgnoreRuleView(id=1, name="chrome", process_name="chrome", protocol="udp")
    assert rule.matches(
        protocol="udp", port=5353, address="0.0.0.0", process_name="chrome.exe", exe=None
    )
    assert not rule.matches(
        protocol="tcp", port=5353, address="0.0.0.0", process_name="chrome.exe", exe=None
    )
    ranged = IgnoreRuleView(id=2, name="r", port_min=6000, port_max=6010)
    assert ranged.matches(protocol="tcp", port=6005, address="::", process_name=None, exe=None)
    assert not ranged.matches(protocol="tcp", port=6011, address="::", process_name=None, exe=None)
    by_exe = IgnoreRuleView(id=3, name="e", exe="*/Program Files/*")
    assert by_exe.matches(
        protocol="tcp", port=1, address="::", process_name="x", exe="C:/Program Files/App/x.exe"
    )
    disabled = IgnoreRuleView(id=4, name="d", protocol="tcp", enabled=False)
    assert (
        first_match(
            [disabled, rule], protocol="udp", port=1, address="::", process_name="chrome", exe=None
        )
        is rule
    )
    assert "ports 6000-6010" in ranged.describe()


def test_ephemeral_range():
    lo, hi = ephemeral_range()
    assert 1024 <= lo < hi <= 65535
    assert is_ephemeral(60000, (49152, 65535)) and not is_ephemeral(8080, (49152, 65535))


# ------------------------------------------------------------ toml writer


def test_toml_writer_round_trip():
    doc = {
        "version": 1,
        "service": [
            {
                "name": 'web "app"',
                "expected_executable": "C:\\node\\node.exe",
                "port": [
                    {"port": 3000, "protocol": "tcp", "address": "*"},
                    {"port": 3001},
                ],
            },
            {"name": "db"},
        ],
        "reservation": [{"port": 5432, "description": "multi\nline"}],
    }
    text = dumps(doc, header="generated")
    assert text.startswith("# generated")
    assert tomllib.loads(text) == doc


# ----------------------------------------------------------------- config


def test_noise_and_alert_config(paths):
    cfg = parse_config(
        {
            "noise": {"ephemeral_udp": False, "flap_window_seconds": 0},
            "alerts": {
                "webhook": [
                    {"url": "https://hooks.example/x", "secret": "s", "min_severity": "error"}
                ]
            },
        },
        paths,
    )
    assert cfg.noise.ephemeral_udp is False and cfg.noise.flap_window_seconds == 0
    hook = cfg.alerts.webhooks[0]
    assert hook.min_severity == "error" and hook.secret == "s"
    public = cfg.as_public_dict()["alerts"]["webhooks"][0]
    assert public == {
        "url": "https://hooks.example/x",
        "min_severity": "error",
        "events": list(hook.events),
        "signed": True,
    }
    assert "secret" not in public and "topsecret" not in repr(hook)  # secret is repr=False


@pytest.mark.parametrize(
    "raw",
    [
        {"alerts": {"webhook": [{"url": "ftp://x"}]}},
        {"alerts": {"webhook": [{"url": "http://x", "min_severity": "loud"}]}},
        {"alerts": {"webhook": [{"url": "http://x", "events": ["nope"]}]}},
        {"alerts": {"webhook": "x"}},
        {"noise": {"noise_retention_days": 0}},
        {"noise": {"flap_window_seconds": -1}},
    ],
)
def test_invalid_noise_alert_config(paths, raw):
    with pytest.raises(ConfigError):
        parse_config(raw, paths)


# --------------------------------------------------------------- projects


def test_project_detection(tmp_path):
    repo = tmp_path / "work" / "myapp"
    (repo / ".git").mkdir(parents=True)
    nested = repo / "src" / "server"
    nested.mkdir(parents=True)
    detector = ProjectDetector()
    info = detector.detect(str(nested))
    assert info is not None and info.name == "myapp" and info.marker == ".git"
    assert Path(info.root) == repo
    assert detector.detect(None) is None
    assert detector.detect("relative/path") is None
    lonely = tmp_path / "nothing" / "here"
    lonely.mkdir(parents=True)
    assert detector.detect(str(lonely)) is None


# ----------------------------------------------------------------- alerts


def test_webhook_delivery_signs_and_retries():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(503 if len(seen) == 1 else 204)

    hook = WebhookConfig(url="http://127.0.0.1:9/hook?token=abc", secret="topsecret")
    client = httpx.Client(transport=httpx.MockTransport(handler))
    payload = alerts_mod.build_payload("conflict.detected", "warning", {"summary": "x"}, "uuid-1")
    report = alerts_mod.deliver(
        hook, payload, client=client, retries=(0.0, 0.0), wait=lambda _s: False
    )
    assert report["ok"] and report["attempts"] == 2
    assert report["url"] == "http://127.0.0.1:9/hook"  # query string (secrets) never reported
    body = seen[-1].content
    expected = "sha256=" + hmac.new(b"topsecret", body, hashlib.sha256).hexdigest()
    assert seen[-1].headers["X-PortRegistry-Signature"] == expected
    assert json.loads(body)["event"] == "conflict.detected"


def test_webhook_client_error_not_retried():
    calls = []
    client = httpx.Client(
        transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(404))
    )
    report = alerts_mod.deliver(
        WebhookConfig(url="http://x/"), {}, client=client, retries=(0.0, 0.0), wait=lambda _s: False
    )
    assert not report["ok"] and len(calls) == 1


def test_webhook_filters():
    hook = WebhookConfig(
        url="http://x/", min_severity="warning", events=("conflict.detected", "alert.test")
    )
    assert alerts_mod.wants(hook, "conflict.detected", "error")
    assert not alerts_mod.wants(hook, "conflict.detected", "info")
    assert not alerts_mod.wants(hook, "docker.unavailable", "warning")
    assert alerts_mod.wants(hook, "alert.test", "info")


def test_dispatcher_queues_only_alert_topic():
    from portregistry.core.events import BusEvent

    dispatcher = alerts_mod.AlertDispatcher((WebhookConfig(url="http://x/"),), "u")
    dispatcher.on_bus_event(BusEvent(1, "ports", "ports.changed", {}))
    dispatcher.on_bus_event(BusEvent(2, "alerts", "conflict.detected", {"severity": "warning"}))
    assert dispatcher.describe()["queued"] == 1
    assert not alerts_mod.AlertDispatcher((), "u").enabled


# --------------------------------------------------------------- autostart


class FakeRegistry:
    def __init__(self):
        self.values: dict[str, str] = {}

    def get(self, name):
        return self.values.get(name)

    def set(self, name, value):
        self.values[name] = value

    def delete(self, name):
        self.values.pop(name, None)


def test_windows_backend_install_uninstall_and_dry_run():
    reg = FakeRegistry()
    backend = autostart.WindowsBackend(registry=reg)
    planned = autostart.install(r"C:\pr home", tray=True, dry_run=True, backend=backend)
    assert reg.values == {}  # dry run changes nothing
    assert {a.target for a in planned} == {"PortRegistry", "PortRegistryTray"}
    assert (
        "daemon run --quiet --home" in planned[0].content and '"C:\\pr home"' in planned[0].content
    )
    autostart.install(None, backend=backend)
    assert backend.status().installed and not backend.status().tray_installed
    autostart.uninstall(backend=backend)
    assert not backend.status().installed


def test_systemd_backend(tmp_path):
    commands = []
    backend = autostart.SystemdBackend(
        base=tmp_path, runner=lambda args: commands.append(args) or 0
    )
    actions = autostart.install("/home/me/pr", tray=False, backend=backend)
    unit = (tmp_path / "portregistry.service").read_text()
    assert "ExecStart=" in unit and "daemon run --quiet --home /home/me/pr" in unit
    assert "Environment=PORTREGISTRY_HOME=/home/me/pr" in unit and "Restart=on-failure" in unit
    assert ["systemctl", "--user", "enable", "--now", "portregistry.service"] in commands
    assert backend.status().installed and any(a.kind == "run" for a in actions)
    autostart.uninstall(backend=backend)
    assert not (tmp_path / "portregistry.service").exists()


def test_systemd_failure_raises(tmp_path):
    backend = autostart.SystemdBackend(base=tmp_path, runner=lambda args: 1)
    with pytest.raises(RuntimeError):
        autostart.install(None, backend=backend)


def test_launchd_and_xdg_backends(tmp_path):
    import plistlib

    commands = []
    launchd = autostart.LaunchdBackend(
        base=tmp_path / "la", runner=lambda a: commands.append(a) or 0
    )
    autostart.install("/h", tray=True, backend=launchd)
    data = plistlib.loads((tmp_path / "la" / "io.portregistry.daemon.plist").read_bytes())
    assert data["RunAtLoad"] is True and data["EnvironmentVariables"] == {"PORTREGISTRY_HOME": "/h"}
    assert data["ProgramArguments"][-3:] == ["--quiet", "--home", "/h"]
    assert launchd.status().tray_installed and any(
        c[:2] == ["launchctl", "bootstrap"] for c in commands
    )
    autostart.uninstall(backend=launchd)
    assert not launchd.status().installed

    xdg = autostart.XdgAutostartBackend(base=tmp_path / "xdg")
    autostart.install(None, backend=xdg)
    assert "Exec=" in (tmp_path / "xdg" / "portregistry.desktop").read_text()
    autostart.uninstall(backend=xdg)
    assert not xdg.status().installed


def test_status_never_raises():
    class Broken:
        mechanism = "x"

        def status(self):
            raise OSError("boom")

    assert autostart.status(Broken()).mechanism == "unknown"


# -------------------------------------------------------------------- tray

STATUS = {
    "summary": {"conflicts": {"error": 0, "warning": 2, "info": 5}, "endpoints": {"total": 10}},
    "discovery": {"stale": False},
}


class FakeClient:
    def __init__(self, status=STATUS, fail=False):
        self.status, self.fail, self.posts = status, fail, []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get(self, path, **params):
        if self.fail:
            raise DaemonNotRunningError("down")
        return self.status

    def post(self, path, body=None):
        if self.fail:
            raise DaemonNotRunningError("down")
        self.posts.append(path)
        return {"url": "http://127.0.0.1:8765/login/link/abc/"}


def test_tray_state_and_actions():
    assert state_from_status(None)[0] == "offline"
    assert state_from_status(STATUS)[0] == "warning"
    assert (
        state_from_status(
            {
                **STATUS,
                "summary": {
                    **STATUS["summary"],
                    "conflicts": {"error": 1, "warning": 0, "info": 0},
                },
            }
        )[0]
        == "error"
    )
    client = FakeClient()
    notes, opened = [], []
    tray = TrayController(
        lambda: client,
        notifier=lambda t, m: notes.append((t, m)),
        opener=opened.append,
        control=object(),
    )
    tray.refresh()
    assert tray.state == "warning" and "2 warning" in tray.conflict_label
    tray.handle_event(
        "alerts", {"type": "conflict.detected", "data": {"summary": "Reserved tcp *:80 is in use"}}
    )
    assert notes == [("Port conflict", "Reserved tcp *:80 is in use")]
    tray.toggle_notifications()
    tray.handle_event("alerts", {"type": "conflict.detected", "data": {"summary": "x"}})
    assert len(notes) == 1
    tray.open_gui("/conflicts/")
    assert opened == ["http://127.0.0.1:8765/login/link/abc/", "http://127.0.0.1:8765/conflicts/"]
    tray.scan_now()
    assert "discovery/scan/" in client.posts


def test_tray_offline():
    notes = []
    tray = TrayController(
        lambda: FakeClient(fail=True), notifier=lambda t, m: notes.append(m), control=object()
    )
    tray.refresh()
    assert tray.state == "offline"
    tray.open_gui()
    assert notes == ["down"]
    assert alert_text({"type": "scan.failed", "data": {"summary": "boom"}}) == (
        "Discovery failed",
        "boom",
    )
