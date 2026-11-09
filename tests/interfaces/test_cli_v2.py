"""CLI tests for v0.2 commands against a mocked daemon API."""

from __future__ import annotations

import json
import tomllib

import httpx
import pytest
from typer.testing import CliRunner

from portregistry.cli import common
from portregistry.cli.main import app
from portregistry.client import ApiClient

NOW = "2026-11-09T10:00:00+00:00"
DISCOVERY = {"last_success_at": NOW, "stale": False}
PORT = {
    "id": 1,
    "protocol": "tcp",
    "address": "0.0.0.0",
    "port": 5432,
    "state": "LISTEN",
    "pid": 42,
    "endpoint": "tcp 0.0.0.0:5432",
    "active": True,
    "first_seen": NOW,
    "label": "PostgreSQL",
    "ignored": None,
    "process": {"id": 3, "pid": 42, "name": "postgres", "project": "db"},
    "docker": [],
}


def page(results):
    return {"count": len(results), "next": None, "previous": None, "results": results}


class Daemon:
    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.conflicts = [
            {
                "severity": "warning",
                "certainty": "definite",
                "type": "occupied_reservation",
                "protocol": "tcp",
                "address": "*",
                "port": 80,
                "title": "t",
                "explanation": "e",
                "id": 1,
            }
        ]

    def body(self, request):
        return json.loads(request.content) if request.content else {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path.removeprefix("/api/v1/")
        params = request.url.params
        if path == "status/":
            return httpx.Response(200, json={"discovery": DISCOVERY})
        if path == "ports/":
            return httpx.Response(
                200, json=page([PORT] if params.get("port") in (None, "5432") else [])
            )
        if path == "ports/1/":
            return httpx.Response(
                200,
                json={
                    **PORT,
                    "process": {
                        **PORT["process"],
                        "exe": "/usr/bin/postgres",
                        "project_name": "db",
                        "project_root": "/srv/db",
                    },
                    "conflicts": [],
                },
            )
        if path == "reservations/" and request.method == "GET":
            return httpx.Response(200, json=page([]))
        if path == "reservations/" and request.method == "POST":
            return httpx.Response(
                201,
                json={"id": 9, "endpoint": f"tcp *:{self.body(request)['port']}", "conflicts": []},
            )
        if path == "ports/free/":
            return httpx.Response(
                200,
                json={
                    "ports": [{"port": 3001, "protocol": "tcp", "label": "Dev server"}],
                    "skipped": {},
                    "note": "advisory",
                    "advisory": True,
                },
            )
        if path == "services/adopt/" and request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "source": "process postgres (pid 42)",
                    "socket_id": 1,
                    "process_id": 3,
                    "service": {
                        "name": "db",
                        "category": "database",
                        "description": "",
                        "expected_executable": "postgres",
                        "expected_working_directory": "/srv/db",
                    },
                    "endpoints": [
                        {"socket_id": 1, "endpoint": "tcp 0.0.0.0:5432", "selected": True}
                    ],
                },
            )
        if path == "services/adopt/" and request.method == "POST":
            return httpx.Response(
                201,
                json={
                    "service": {"id": 5, "name": self.body(request)["service"]["name"]},
                    "reservations": [{"id": 1}],
                },
            )
        if path == "ports/timeline/":
            return httpx.Response(
                200,
                json={
                    "window": {"start": "2026-11-02T10:00:00+00:00", "end": NOW, "days": 7},
                    "label": "PostgreSQL",
                    "note": "n",
                    "reservations": [],
                    "lanes": [
                        {
                            "owner": "postgres (pid 42)",
                            "endpoint": "tcp 0.0.0.0:5432",
                            "intervals": [{"start": "2026-11-05T10:00:00+00:00", "end": NOW}],
                        }
                    ],
                },
            )
        if path == "conflicts/":
            return httpx.Response(200, json=page(self.conflicts))
        if path == "registry/apply/":
            body = self.body(request)
            return httpx.Response(
                200,
                json={
                    "source": body["source"],
                    "dry_run": body.get("dry_run", False),
                    "applied": not body.get("dry_run"),
                    "changes": 1,
                    "services": {"create": ["web"], "update": [], "unchanged": [], "prune": []},
                    "reservations": {
                        "create": ["tcp *:3000 (web)"],
                        "reactivate_or_update": [],
                        "unchanged": [],
                        "release": [],
                    },
                },
            )
        if path == "registry/export/":
            return httpx.Response(
                200,
                json={
                    "version": 1,
                    "service": [
                        {"name": "web", "port": [{"port": 3000, "protocol": "tcp", "address": "*"}]}
                    ],
                },
            )
        if path == "processes/":
            return httpx.Response(200, json=page([]))
        if path == "ignore-rules/" and request.method == "POST":
            return httpx.Response(
                201,
                json={
                    "id": 4,
                    "name": self.body(request)["name"],
                    "describe": "process chrome*, UDP",
                },
            )
        if path == "ports/1/known/":
            return httpx.Response(
                201, json={"id": 5, "name": "Known: postgres on tcp 0.0.0.0:5432"}
            )
        if path == "auth/rotate-token/":
            return httpx.Response(
                200, json={"rotated": True, "sessions_revoked": 2, "token_file": "/x/token"}
            )
        if path == "alerts/test/":
            return httpx.Response(
                200, json={"results": [{"url": "http://hook/", "ok": False, "error": "HTTP 500"}]}
            )
        return httpx.Response(
            404, json={"error": {"code": "not_found", "message": path, "details": {}}}
        )


@pytest.fixture
def daemon():
    mock = Daemon()
    common.set_client_factory(
        lambda: ApiClient("http://daemon", "tok", transport=httpx.MockTransport(mock))
    )
    yield mock
    common.reset_client_factory()


runner = CliRunner()


def invoke(*args, **kwargs):
    return runner.invoke(app, list(args), env={"COLUMNS": "200"}, **kwargs)


def test_who(daemon):
    out = invoke("who", "5432").output
    assert "PostgreSQL" in out and "postgres" in out and "project: db" in out
    assert "Nothing is bound" in invoke("who", "1").output


def test_free_and_reserve(daemon):
    result = invoke("free", "--range", "3000-3100", "--reserve")
    assert result.exit_code == 0 and "3001" in result.output and "Reserved #9" in result.output
    assert json.loads(daemon.requests[-1].content)["port"] == 3001
    assert daemon.requests[0].url.params["range"] == "3000-3100"


def test_adopt_with_overrides(daemon):
    result = invoke("adopt", "5432", "--name", "pg", "--yes")
    assert result.exit_code == 0 and "'pg' registered" in result.output
    sent = json.loads(daemon.requests[-1].content)
    assert sent["service"]["name"] == "pg" and sent["socket_ids"] == [1]


def test_timeline_text_bars(daemon):
    out = invoke("timeline", "5432").output
    assert "postgres (pid 42)" in out and "█" in out


def test_conflicts_fail_on(daemon):
    assert invoke("conflicts", "--fail-on", "warning").exit_code == 5
    assert invoke("conflicts", "--fail-on", "error").exit_code == 0
    daemon.conflicts = []
    assert invoke("conflicts", "--fail-on", "warning").exit_code == 0


def test_apply_export_init(daemon, tmp_path, monkeypatch):
    manifest = tmp_path / "portregistry.toml"
    manifest.write_text(
        'version = 1\n[[service]]\nname = "web"\nexpected_working_directory = "app"\n',
        encoding="utf-8",
    )
    dry = invoke("apply", str(manifest), "--dry-run")
    assert dry.exit_code == 0 and "Dry run" in dry.output
    sent = json.loads(daemon.requests[-1].content)
    assert sent["source"] == str(manifest.resolve())
    assert sent["document"]["service"][0]["expected_working_directory"] == str(
        (tmp_path / "app").resolve()
    )
    applied = invoke("apply", str(manifest))
    assert "Applied 1 change" in applied.output
    exported = invoke("export")
    assert tomllib.loads(exported.output)["service"][0]["name"] == "web"
    target = tmp_path / "out.toml"
    assert invoke("export", "-f", str(target)).exit_code == 0 and target.exists()
    assert invoke("export", "-f", str(target)).exit_code != 0  # refuses to overwrite
    monkeypatch.chdir(tmp_path)
    init_file = tmp_path / "new.toml"
    assert invoke("init", "-f", str(init_file)).exit_code == 0
    assert "version = 1" in init_file.read_text(encoding="utf-8")
    missing = invoke("apply", str(tmp_path / "missing.toml"))
    assert "Manifest not found" in str(missing.exception)


def test_ignore_and_known(daemon):
    added = invoke(
        "ignore",
        "add",
        "--name",
        "chrome",
        "--process",
        "chrome*",
        "--protocol",
        "udp",
        "--port",
        "5000-6000",
    )
    assert added.exit_code == 0 and "Rule #4" in added.output
    body = json.loads(daemon.requests[-1].content)
    assert (body["port_min"], body["port_max"], body["suppress_conflicts"]) == (5000, 6000, True)
    assert "Known: postgres" in invoke("ignore", "known", "1").output


def test_token_rotate_never_prints_token(daemon):
    out = invoke("token", "rotate").output
    assert "Token rotated" in out and "2 browser session" in out


def test_alerts_test_failure_exit_code(daemon):
    result = invoke("alerts", "test")
    assert result.exit_code == 1 and "HTTP 500" in result.output


def test_daemon_install_dry_run_uses_backend(monkeypatch, tmp_path):
    from portregistry.daemon import autostart

    class Fake(autostart.XdgAutostartBackend):
        executed = False

        def execute(self, actions):
            Fake.executed = True

    monkeypatch.setattr(autostart, "default_backend", lambda: Fake(base=tmp_path))
    result = invoke("daemon", "install", "--tray", "--dry-run")
    assert (
        result.exit_code == 0
        and "Would:" in result.output
        and "portregistry-tray.desktop" in result.output
    )
    assert not Fake.executed
    assert "not installed" in invoke("daemon", "autostart").output


def test_doctor_reports_daemon_down(monkeypatch, tmp_path):
    monkeypatch.setenv("PORTREGISTRY_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PORTREGISTRY_PORT", "1")  # nothing listens there
    result = invoke("doctor", "-o", "json")
    data = json.loads(result.output)
    names = {c["name"]: c for c in data["checks"]}
    assert result.exit_code == 1 and names["daemon"]["status"] == "fail"
    assert names["python"]["status"] == "ok" and names["config"]["status"] == "ok"
    assert names["token.file"]["status"] == "warn"


def test_new_commands_in_help():
    out = invoke("--help").output
    for name in (
        "who",
        "free",
        "adopt",
        "timeline",
        "doctor",
        "apply",
        "export",
        "init",
        "tray",
        "token",
        "alerts",
        "ignore",
        "filters",
    ):
        assert name in out
