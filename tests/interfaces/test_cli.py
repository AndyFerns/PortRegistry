"""CLI commands against a mocked daemon API (httpx MockTransport)."""

import json
import sys

import httpx
import pytest
from typer.testing import CliRunner

from portregistry.cli import common
from portregistry.cli.main import app, main
from portregistry.client import ApiClient
from portregistry.exceptions import ApiError

NOW = "2026-11-09T10:00:00+00:00"
PORT = {
    "id": 1,
    "protocol": "tcp",
    "family": "ipv4",
    "address": "0.0.0.0",
    "port": 8080,
    "state": "LISTEN",
    "pid": 42,
    "endpoint": "tcp 0.0.0.0:8080",
    "active": True,
    "first_seen": NOW,
    "last_seen": NOW,
    "process": {"id": 3, "pid": 42, "name": "node", "exe": "/usr/bin/node", "username": "me"},
    "docker": [],
}
CONFLICT = {
    "id": 1,
    "severity": "warning",
    "certainty": "definite",
    "type": "occupied_reservation",
    "protocol": "tcp",
    "address": "*",
    "port": 8080,
    "title": "Reserved tcp *:8080 is in use",
    "explanation": "Reservation #1 has no associated service, but node (pid 42) is bound.",
}
STATUS = {
    "daemon": {"version": "0.1.0", "pid": 1, "base_url": "http://x", "uptime_seconds": 3},
    "machine": {
        "hostname": "h",
        "os_name": "Linux",
        "os_version": "6",
        "architecture": "x86_64",
        "uuid": "u",
    },
    "discovery": {
        "last_scan_status": "complete",
        "last_scan_at": NOW,
        "last_success_at": NOW,
        "stale": False,
    },
    "providers": {
        "native": {"state": "ok", "message": ""},
        "docker": {"state": "unavailable", "message": "nope"},
    },
    "summary": {
        "endpoints": {"total": 1, "tcp": 1, "udp": 0, "ipv4": 1, "ipv6": 0, "unresolved_owner": 0},
        "processes": 1,
        "services": 0,
        "reservations": {"active": 0, "attention": 0},
        "conflicts": {"error": 0, "warning": 1, "info": 0},
        "containers": {"running": 0, "present": 0},
    },
    "platform": {"elevated": False},
}


def page(results):
    return {"count": len(results), "next": None, "previous": None, "results": results}


class MockDaemon:
    def __init__(self):
        self.requests = []
        self.ticket_polls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["Authorization"] == "Bearer tok"
        path = request.url.path.removeprefix("/api/v1/")
        body = json.loads(request.content) if request.content else None
        if path == "status/":
            return httpx.Response(200, json=STATUS)
        if path == "ports/":
            return httpx.Response(200, json=page([PORT]))
        if path == "conflicts/":
            return httpx.Response(200, json=page([CONFLICT]))
        if path == "discovery/scan/" and request.method == "POST":
            return httpx.Response(
                202, json={"ticket": 5, "status": "queued", "coalesced_requests": 0}
            )
        if path == "discovery/scan/5/":
            self.ticket_polls += 1
            return httpx.Response(
                200,
                json={
                    "ticket": 5,
                    "status": "done",
                    "scan_id": 9,
                    "coalesced_requests": 0,
                    "result": {
                        "status": "complete",
                        "socket_count": 1,
                        "process_count": 1,
                        "appeared": 1,
                        "disappeared": 0,
                    },
                    "scan": {"duration_ms": 12},
                },
            )
        if path == "reservations/" and request.method == "POST":
            if body["port"] == 0:
                return httpx.Response(
                    400,
                    json={
                        "error": {
                            "code": "validation_error",
                            "message": "Invalid reservation.",
                            "details": {"fields": {"port": ["Port must be between 1 and 65535."]}},
                        }
                    },
                )
            return httpx.Response(
                201,
                json={"id": 1, "endpoint": "tcp *:8080", "service": None, "conflicts": [CONFLICT]},
            )
        if path == "reservations/check/":
            return httpx.Response(200, json={"findings": [], "conflict_free": True})
        if path == "services/" and request.method == "POST":
            return httpx.Response(201, json={"id": 2, **body})
        if path == "history/":
            return httpx.Response(
                200,
                json=page(
                    [
                        {
                            "id": 1,
                            "timestamp": NOW,
                            "type": "endpoint.appeared",
                            "severity": "info",
                            "summary": "opened",
                        }
                    ]
                ),
            )
        return httpx.Response(
            404, json={"error": {"code": "not_found", "message": f"no {path}", "details": {}}}
        )


@pytest.fixture
def daemon():
    mock = MockDaemon()
    common.set_client_factory(
        lambda: ApiClient("http://daemon", "tok", transport=httpx.MockTransport(mock))
    )
    yield mock
    common.reset_client_factory()


runner = CliRunner()


def invoke(*args):
    return runner.invoke(app, list(args), env={"COLUMNS": "200"})


def test_status(daemon):
    result = invoke("status")
    assert result.exit_code == 0, result.output
    assert "1 active (1 TCP" in result.output and "unavailable" in result.output


def test_ports_table_json_csv(daemon):
    table = invoke("ports", "--port", "8080")
    assert table.exit_code == 0 and "node" in table.output and "8080" in table.output
    assert daemon.requests[0].url.params["port"] == "8080"
    as_json = json.loads(invoke("ports", "-o", "json").output)
    assert as_json[0]["process"]["name"] == "node"
    csv_out = invoke("ports", "-o", "csv").output.splitlines()
    assert csv_out[0].startswith("id,protocol,family") and "node" in csv_out[1]


def test_scan_waits_for_ticket(daemon):
    result = invoke("scan", "--protocol", "tcp")
    assert result.exit_code == 0, result.output
    assert "Scan #9 complete" in result.output
    assert daemon.ticket_polls == 1


def test_conflicts_default_hides_info(daemon):
    result = invoke("conflicts")
    assert "occupied_reservation" in result.output
    assert daemon.requests[-1].url.params["min_severity"] == "warning"
    invoke("conflicts", "--all")
    assert "min_severity" not in daemon.requests[-1].url.params


def test_reserve_reports_conflicts(daemon):
    result = invoke("reserve", "8080", "-d", "demo")
    assert result.exit_code == 0
    assert "Reservation #1 created" in result.output and "is in use" in result.output
    sent = json.loads(daemon.requests[-1].content)
    assert sent == {"port": 8080, "protocol": "tcp", "bind_address": "*", "description": "demo"}


def test_reserve_dry_run(daemon):
    result = invoke("reserve", "9999", "--dry-run")
    assert "No conflicts detected" in result.output
    assert daemon.requests[-1].url.path.endswith("reservations/check/")


def test_validation_error_is_raised_for_main(daemon):
    result = invoke("reserve", "0")
    assert isinstance(result.exception, ApiError)
    assert result.exception.details["fields"]["port"]


def test_service_add(daemon):
    result = invoke("service", "add", "web", "--exe", "nginx")
    assert result.exit_code == 0 and "registered" in result.output
    assert json.loads(daemon.requests[-1].content) == {
        "name": "web",
        "expected_executable": "nginx",
    }


def test_history_json(daemon):
    data = json.loads(invoke("history", "-o", "json").output)
    assert data[0]["type"] == "endpoint.appeared"


def test_main_maps_errors_to_exit_codes(daemon, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["portregistry", "reserve", "0"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    assert "Port must be between" in capsys.readouterr().err


def test_daemon_not_running_exit_code(monkeypatch, capsys):
    def refuse(request):
        raise httpx.ConnectError("refused", request=request)

    common.set_client_factory(
        lambda: ApiClient("http://127.0.0.1:1", "tok", transport=httpx.MockTransport(refuse))
    )
    try:
        monkeypatch.setattr(sys, "argv", ["portregistry", "status"])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 3
        assert "portregistry daemon start" in capsys.readouterr().err
    finally:
        common.reset_client_factory()


def test_help_lists_prd_commands():
    output = invoke("--help").output
    for command in (
        "daemon",
        "scan",
        "ports",
        "service",
        "reserve",
        "reservations",
        "release",
        "conflicts",
        "history",
        "machines",
        "report",
        "gui",
        "tui",
    ):
        assert command in output
