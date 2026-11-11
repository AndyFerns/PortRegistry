"""TUI stop dialog: two steps, PID must be typed, Stop disabled until it matches."""

from __future__ import annotations

import asyncio

from textual.widgets import Button, DataTable, Input

from portregistry.tui.app import PortRegistryApp
from portregistry.tui.screens import StopScreen, assessment_text
from tests.interfaces.test_cli_control import ASSESSMENT, OP
from tests.interfaces.test_tui import PORTS, FakeClient

PORTS_WITH_OWNER = [
    {**PORTS[0], "process": {**PORTS[0]["process"], "id": 3}},
    *PORTS[1:],
]


class StopClient(FakeClient):
    def __init__(self, assessment=None):
        super().__init__()
        self.assessment = assessment or ASSESSMENT
        self.calls: list[tuple[str, str, dict]] = []

    async def results(self, path, **params):
        if path == "ports/":
            return PORTS_WITH_OWNER
        return await super().results(path, **params)

    async def request(self, method, path, *, params=None, json_body=None, headers=None, **kw):
        self.calls.append((method, path, headers or {}))
        if path.endswith("stop/preview/"):
            return {**self.assessment, "mode": (params or {}).get("mode", "process")}
        raise AssertionError(path)

    async def post(self, path, body=None, *, headers=None, timeout=None):
        self.calls.append(("POST", path, headers or {}))
        self.posts.append((path, body))
        if path == "processes/3/stop/request/":
            return {"code": "c0de", "expires_in": 30, "assessment": self.assessment}
        if path == "processes/stop/confirm/":
            return OP
        return await super().post(path, body)


def run(coro):
    return asyncio.run(coro)


def test_stop_dialog_two_steps_and_typed_pid():
    async def scenario():
        client = StopClient()
        app = PortRegistryApp(lambda: client, live_updates=False)
        async with app.run_test(size=(150, 50)) as pilot:
            await pilot.pause(0.2)
            app.action_show_tab("ports")
            app.query_one("#ports-table", DataTable).focus()
            await pilot.press("X")
            await pilot.pause(0.3)
            screen = app.screen
            assert isinstance(screen, StopScreen)
            assert client.calls[0][2]["X-PortRegistry-Client"] == "tui"
            assert screen.query_one("#confirm", Button).disabled
            assert screen.query_one("#pid", Input).disabled
            assert not any(p == "processes/3/stop/request/" for p, _ in client.posts)

            await pilot.click("#continue")  # step 1: get the code
            await pilot.pause(0.3)
            assert ("processes/3/stop/request/", {"mode": "process", "force": False}) in (
                client.posts
            )
            pid_input = screen.query_one("#pid", Input)
            assert not pid_input.disabled
            pid_input.value = "4241"
            await pilot.pause(0.1)
            assert screen.query_one("#confirm", Button).disabled
            pid_input.value = "4242"
            await pilot.pause(0.1)
            assert not screen.query_one("#confirm", Button).disabled

            await pilot.click("#confirm")  # step 2
            await pilot.pause(0.3)
            assert not isinstance(app.screen, StopScreen)
            assert ("processes/stop/confirm/", {"code": "c0de", "pid": "4242"}) in client.posts

    run(scenario())


def test_stop_dialog_disabled_control_offers_commands_only():
    async def scenario():
        client = StopClient(
            {
                **ASSESSMENT,
                "control_enabled": False,
                "can_request": False,
                "control": {"enabled": False, "reason": "Process control is off."},
            }
        )
        app = PortRegistryApp(lambda: client, live_updates=False)
        async with app.run_test(size=(150, 50)) as pilot:
            await pilot.pause(0.2)
            app.action_show_tab("ports")
            app.query_one("#ports-table", DataTable).focus()
            await pilot.press("X")
            await pilot.pause(0.3)
            screen = app.screen
            assert isinstance(screen, StopScreen)
            assert screen.query_one("#continue", Button).disabled
            await pilot.press("escape")
            await pilot.pause(0.1)
            assert not isinstance(app.screen, StopScreen)
            assert client.posts == []

    run(scenario())


def test_assessment_text_never_interprets_markup():
    text = assessment_text(
        {**ASSESSMENT, "identity": {**ASSESSMENT["identity"], "name": "[bold]x[/bold]"}}
    )
    assert "[bold]x[/bold]" in text.plain and "kill -TERM 4242" in text.plain
