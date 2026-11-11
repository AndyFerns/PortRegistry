"""CLI tests for `portregistry stop` (mock daemon transport; nothing is stopped)."""

from __future__ import annotations

import json

import httpx
import pytest
from typer.testing import CliRunner

from portregistry.cli import common, control_cmds
from portregistry.cli.main import app
from portregistry.client import ApiClient

ASSESSMENT = {
    "process_id": 3,
    "mode": "process",
    "force": False,
    "control": {"enabled": True, "reason": ""},
    "control_enabled": True,
    "identity": {"process_id": 3, "pid": 4242, "name": "node", "cmdline": ["node", "app.js"]},
    "live": True,
    "allowed": True,
    "can_request": True,
    "reasons": [],
    "warnings": [],
    "target": {
        "pid": 4242,
        "cmdline": ["node", "app.js"],
        "cwd": "/srv/shop",
        "username": "alice",
    },
    "parent_chain": [{"pid": 10, "name": "bash", "protected": False}],
    "members": [
        {
            "pid": 4242,
            "name": "node",
            "depth": 0,
            "method": "graceful",
            "refusals": [],
            "ports": ["tcp 0.0.0.0:3000"],
        }
    ],
    "method": "graceful",
    "method_label": "Graceful stop (SIGTERM).",
    "graceful": True,
    "impact": {"processes": 1, "ports": ["tcp 0.0.0.0:3000"], "services": ["shop"]},
    "docker": [],
    "commands": [{"label": "Graceful stop (SIGTERM)", "command": "kill -TERM 4242"}],
    "command_note": "Copy-and-run alternative.",
}

OP = {
    "id": "op1",
    "state": "done",
    "outcome": "stopped",
    "message": "Stopped.",
    "grace_seconds": 10,
    "members": [
        {"pid": 4242, "name": "node", "method": "graceful", "result": "stopped", "detail": "ok"}
    ],
}


def page(results):
    return {"count": len(results), "next": None, "previous": None, "results": results}


class Daemon:
    def __init__(self, assessment=None):
        self.assessment = assessment or ASSESSMENT
        self.requests: list[httpx.Request] = []

    def paths(self, method=None):
        return [
            r.url.path.removeprefix("/api/v1/")
            for r in self.requests
            if method is None or r.method == method
        ]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path.removeprefix("/api/v1/")
        if path == "ports/":
            owners = [{"id": 3, "pid": 4242, "name": "node"}]
            if request.url.params.get("port") == "80":
                owners.append({"id": 4, "pid": 4243, "name": "nginx"})
            return httpx.Response(
                200,
                json=page(
                    [{"id": i, "endpoint": f"tcp :{i}", "process": p} for i, p in enumerate(owners)]
                ),
            )
        if path == "processes/3/stop/preview/":
            return httpx.Response(200, json=self.assessment)
        if path == "processes/3/stop/request/":
            return httpx.Response(
                201, json={"code": "c0de", "expires_in": 30, "assessment": self.assessment}
            )
        if path == "processes/stop/confirm/":
            body = json.loads(request.content)
            if str(body.get("pid")) != "4242":
                return httpx.Response(
                    409,
                    json={
                        "error": {
                            "code": "stop_refused",
                            "message": "The PID you typed does not match.",
                            "details": {},
                        }
                    },
                )
            return httpx.Response(200, json=OP)
        return httpx.Response(404, json={"error": {"code": "not_found", "message": path}})


@pytest.fixture
def daemon(monkeypatch):
    mock = Daemon()
    common.set_client_factory(
        lambda: ApiClient("http://daemon", "tok", transport=httpx.MockTransport(mock))
    )
    monkeypatch.setattr(control_cmds, "_is_interactive", lambda: True)
    yield mock
    common.reset_client_factory()


runner = CliRunner()


def invoke(*args, **kwargs):
    return runner.invoke(app, list(args), env={"COLUMNS": "200"}, **kwargs)


def test_stop_by_port_with_typed_pid(daemon):
    result = invoke("stop", "3000", input="4242\n")
    assert result.exit_code == 0, result.output
    assert "node app.js" in result.output and "/srv/shop" in result.output
    assert "bash (10)" in result.output and "shop" in result.output
    assert "Stopped." in result.output
    confirm = [r for r in daemon.requests if r.url.path.endswith("stop/confirm/")][0]
    assert json.loads(confirm.content) == {"code": "c0de", "pid": "4242"}
    assert confirm.headers["X-PortRegistry-Client"] == "cli"
    assert confirm.headers["X-PortRegistry-Client-Ancestors"]


def test_wrong_pid_is_sent_and_refused_by_the_daemon(daemon):
    result = invoke("stop", "--process", "3", input="1\n")
    assert result.exit_code == 1
    assert "processes/stop/confirm/" in daemon.paths("POST")


def test_empty_answer_cancels_without_confirming(daemon):
    result = invoke("stop", "--process", "3", input="\n")
    assert result.exit_code == 1 and "Nothing was stopped" in result.output
    assert "processes/stop/confirm/" not in daemon.paths("POST")


def test_non_interactive_refuses_before_requesting_a_code(daemon, monkeypatch):
    monkeypatch.setattr(control_cmds, "_is_interactive", lambda: False)
    result = invoke("stop", "--process", "3")
    assert result.exit_code == control_cmds.EXIT_NOT_INTERACTIVE
    assert "interactive terminal" in result.output
    assert daemon.paths("POST") == []


def test_there_is_no_yes_flag(daemon):
    result = invoke("stop", "--process", "3", "--yes")
    assert result.exit_code == 2 and "No such option" in result.output
    assert daemon.paths("POST") == []
    import typer.main

    command = typer.main.get_command(app).commands["stop"]
    options = {opt for param in command.params for opt in param.opts + param.secondary_opts}
    assert "--show-command" in options
    assert not options & {"--yes", "-y", "--no-confirm", "--assume-yes"}


def test_show_command_never_calls_stop_endpoints(daemon):
    result = invoke("stop", "--process", "3", "--show-command")
    assert result.exit_code == 0 and "kill -TERM 4242" in result.output
    assert daemon.paths("POST") == []


def test_disabled_control_prints_reason_and_commands(daemon):
    daemon.assessment = {
        **ASSESSMENT,
        "control_enabled": False,
        "can_request": False,
        "control": {"enabled": False, "reason": "Process control is off."},
    }
    result = invoke("stop", "--process", "3")
    assert result.exit_code == control_cmds.EXIT_REFUSED
    assert "Process control is off." in result.output and "kill -TERM 4242" in result.output
    assert daemon.paths("POST") == []


def test_refused_process_exits_without_request(daemon):
    daemon.assessment = {
        **ASSESSMENT,
        "allowed": False,
        "can_request": False,
        "reasons": ["This is the PortRegistry daemon itself."],
    }
    result = invoke("stop", "--process", "3")
    assert result.exit_code == control_cmds.EXIT_REFUSED
    assert "daemon itself" in result.output and daemon.paths("POST") == []


def test_port_with_several_owners_asks_to_choose(daemon):
    result = invoke("stop", "80")
    assert result.exit_code == control_cmds.EXIT_REFUSED
    assert "--process 3" in result.output and "--process 4" in result.output


def test_tree_and_force_are_sent(daemon):
    invoke("stop", "--process", "3", "--tree", "--force", input="4242\n")
    preview = [r for r in daemon.requests if r.url.path.endswith("stop/preview/")][0]
    assert preview.url.params["mode"] == "tree" and preview.url.params["force"] == "1"
    request = [r for r in daemon.requests if r.url.path.endswith("stop/request/")][0]
    assert json.loads(request.content) == {"mode": "tree", "force": True}
