"""Textual pilot tests against a fake API client (no daemon, no network)."""

import asyncio

from textual.widgets import DataTable, Input, Static, TabbedContent

from portregistry.exceptions import ApiError, DaemonNotRunningError
from portregistry.tui.app import PortRegistryApp
from portregistry.tui.screens import DetailScreen, ReservationFormScreen, ServiceFormScreen

NOW = "2026-11-09T10:00:00+00:00"

STATUS = {
    "daemon": {
        "version": "0.1.0",
        "pid": 1,
        "base_url": "http://127.0.0.1:8765",
        "uptime_seconds": 5,
    },
    "machine": {"hostname": "testhost", "uuid": "u-1", "os_name": "Linux", "os_version": "6"},
    "discovery": {"last_success_at": NOW, "stale": False},
    "providers": {
        "native": {"state": "ok", "message": ""},
        "docker": {"state": "unavailable", "message": "Docker daemon is not reachable."},
    },
    "summary": {
        "endpoints": {"total": 2, "tcp": 1, "udp": 1, "ipv4": 2, "ipv6": 0, "unresolved_owner": 0},
        "processes": 1,
        "services": 1,
        "reservations": {"active": 1, "attention": 1},
        "conflicts": {"error": 0, "warning": 1, "info": 1},
        "containers": {"running": 0, "present": 0},
    },
    "platform": {"elevated": False, "notes": ["note"]},
    "config": {"native_interval": 10},
    "scheduler": {"next_native_in": 3, "current_job": None},
}

PORTS = [
    {
        "id": 1,
        "protocol": "tcp",
        "address": "0.0.0.0",
        "port": 8080,
        "state": "LISTEN",
        "pid": 42,
        "process": {"name": "[bold]evil[/bold]", "username": "me"},
        "docker": [],
        "first_seen": NOW,
        "endpoint": "tcp 0.0.0.0:8080",
    },
    {
        "id": 2,
        "protocol": "udp",
        "address": "0.0.0.0",
        "port": 5353,
        "state": "BOUND",
        "pid": 42,
        "process": {"name": "mdns", "username": "me"},
        "docker": [],
        "first_seen": NOW,
        "endpoint": "udp 0.0.0.0:5353",
    },
]
CONFLICT = {
    "severity": "warning",
    "certainty": "definite",
    "type": "occupied_reservation",
    "protocol": "tcp",
    "address": "*",
    "port": 8080,
    "title": "Reserved tcp *:8080 is in use",
    "explanation": "x",
}
RESERVATIONS = [
    {
        "id": 7,
        "endpoint": "tcp *:8080",
        "status": "active",
        "display_status": "attention",
        "service": None,
        "conflicts": [CONFLICT],
        "description": "demo",
        "port": 8080,
        "protocol": "tcp",
    }
]


class FakeClient:
    def __init__(self, fail=False):
        self.fail = fail
        self.posts = []
        self.queries = []
        self.closed = False

    async def get(self, path, **params):
        if self.fail:
            raise DaemonNotRunningError("Cannot reach the PortRegistry daemon")
        if path == "status/":
            return STATUS
        return {"id": 1, "path": path}

    async def results(self, path, **params):
        if self.fail:
            raise DaemonNotRunningError("Cannot reach the PortRegistry daemon")
        self.queries.append((path, params))
        if path == "ports/":
            q = params.get("q")
            return [p for p in PORTS if not q or q in str(p["port"])]
        return {
            "services/": [
                {
                    "id": 3,
                    "name": "web",
                    "category": "web",
                    "expected_executable": "nginx",
                    "active_reservation_count": 1,
                }
            ],
            "reservations/": RESERVATIONS,
            "conflicts/": [CONFLICT],
            "machines/": [
                {
                    "hostname": "testhost",
                    "uuid": "u-1",
                    "os_name": "Linux",
                    "os_version": "6",
                    "architecture": "x86_64",
                    "online": True,
                    "last_seen": NOW,
                }
            ],
            "history/": [
                {
                    "timestamp": NOW,
                    "type": "endpoint.appeared",
                    "severity": "info",
                    "summary": "tcp 0.0.0.0:8080 opened",
                }
            ],
        }.get(path, [])

    async def post(self, path, body=None):
        self.posts.append((path, body))
        if path == "services/" and not (body or {}).get("name"):
            raise ApiError(
                400,
                "validation_error",
                "Invalid service.",
                {"fields": {"name": ["This field is required."]}},
            )
        if path == "services/":
            return {"id": 9, **body}
        if path == "reservations/check/":
            return {"findings": [CONFLICT]}
        if path == "reservations/":
            return {"id": 8, "conflicts": [], **body}
        return {}

    async def stream_events(self):
        yield "hello", {"resync": True}
        await asyncio.Event().wait()

    async def aclose(self):
        self.closed = True


def run(coro):
    return asyncio.run(coro)


def test_tables_populated_and_markup_not_interpreted():
    async def scenario():
        client = FakeClient()
        app = PortRegistryApp(lambda: client)
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause(0.3)
            ports = app.query_one("#ports-table", DataTable)
            assert ports.row_count == 2
            # Untrusted process name rendered literally, not as rich markup.
            assert str(ports.get_row_at(0)[5]) == "[bold]evil[/bold]"
            assert app.query_one("#reservations-table", DataTable).row_count == 1
            assert app.query_one("#conflicts-table", DataTable).row_count == 1
            assert app.query_one("#history-table", DataTable).row_count == 1
            body = str(app.query_one("#dashboard-body", Static).render())
            assert "testhost" in body and "unavailable" in body
            assert app.connected
        assert client.closed

    run(scenario())


def test_search_and_tab_navigation():
    async def scenario():
        client = FakeClient()
        app = PortRegistryApp(lambda: client, live_updates=False)
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause(0.2)
            await pilot.press("slash")
            assert app.query_one(TabbedContent).active == "ports"
            assert app.focused is app.query_one("#ports-search", Input)
            await pilot.press("5", "3", "5", "3", "enter")
            await pilot.pause(0.3)
            assert app.query_one("#ports-table", DataTable).row_count == 1
            assert ("ports/", {"q": "5353", "limit": 1000}) in client.queries
            await pilot.press("escape")
            app.action_show_tab("history")
            assert app.query_one(TabbedContent).active == "history"

    run(scenario())


def test_enter_opens_details():
    async def scenario():
        app = PortRegistryApp(lambda: FakeClient(), live_updates=False)
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause(0.2)
            app.action_show_tab("ports")
            app.query_one("#ports-table", DataTable).focus()
            await pilot.press("enter")
            await pilot.pause(0.2)
            assert isinstance(app.screen, DetailScreen)
            await pilot.press("escape")
            await pilot.pause(0.1)
            assert not isinstance(app.screen, DetailScreen)

    run(scenario())


def test_add_service_form_validation_and_success():
    async def scenario():
        client = FakeClient()
        app = PortRegistryApp(lambda: client, live_updates=False)
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause(0.2)
            await pilot.press("a")
            await pilot.pause(0.1)
            assert isinstance(app.screen, ServiceFormScreen)
            await pilot.click("#save")
            await pilot.pause(0.2)
            assert "required" in str(app.screen.query_one("#error").render())
            app.screen.query_one("#name", Input).value = "api"
            await pilot.click("#save")
            await pilot.pause(0.3)
            assert not isinstance(app.screen, ServiceFormScreen)
        assert (
            "services/",
            {
                "name": "api",
                "expected_executable": "",
                "expected_working_directory": "",
                "category": "",
                "description": "",
            },
        ) in client.posts

    run(scenario())


def test_new_reservation_prefills_from_selected_port_and_checks():
    async def scenario():
        client = FakeClient()
        app = PortRegistryApp(lambda: client, live_updates=False)
        async with app.run_test(size=(140, 45)) as pilot:
            await pilot.pause(0.2)
            app.action_show_tab("ports")
            app.query_one("#ports-table", DataTable).focus()
            await pilot.press("n")
            await pilot.pause(0.2)
            assert isinstance(app.screen, ReservationFormScreen)
            assert app.screen.query_one("#port", Input).value == "8080"
            await pilot.click("#check")
            await pilot.pause(0.2)
            assert "in use" in str(app.screen.query_one("#findings").render())
            await pilot.click("#save")
            await pilot.pause(0.3)
        assert any(p == "reservations/" and b["port"] == 8080 for p, b in client.posts)

    run(scenario())


def test_daemon_unreachable_shows_offline_state():
    async def scenario():
        app = PortRegistryApp(lambda: FakeClient(fail=True), live_updates=False)
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause(0.3)
            status = app.query_one("#status", Static)
            assert "unreachable" in str(status.render())
            assert status.has_class("offline")

    run(scenario())
