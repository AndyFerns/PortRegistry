"""PortRegistry Textual application.

Uses the daemon API only (async httpx), never the database or local discovery.
Live updates arrive via SSE; on disconnect the last data stays visible with a
warning and the stream reconnects with backoff, then refreshes everything.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.widgets import DataTable, Footer, Header, Input, Static, TabbedContent, TabPane

from portregistry import __version__
from portregistry.client import AsyncApiClient, control_headers
from portregistry.tui.screens import (
    AdoptScreen,
    ConfirmScreen,
    DetailScreen,
    HelpScreen,
    ReservationFormScreen,
    ServiceFormScreen,
    StopScreen,
    format_error,
    plain,
)

TABS = [
    "dashboard",
    "ports",
    "services",
    "reservations",
    "conflicts",
    "machines",
    "history",
    "settings",
]
SEVERITY_STYLE = {"error": "bold red", "warning": "yellow", "info": "cyan"}
STATE_STYLE = {
    "ok": "green",
    "complete": "green",
    "unavailable": "red",
    "failed": "red",
    "degraded": "yellow",
    "partial": "yellow",
    "disabled": "dim",
    "unknown": "dim",
}


def ago(value: str | None) -> str:
    if not value:
        return "never"
    try:
        seconds = (datetime.now(UTC) - datetime.fromisoformat(value)).total_seconds()
    except ValueError:
        return value
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def styled(value: Any, styles: dict[str, str]) -> Text:
    text = str(value or "-")
    return Text(text, style=styles.get(text, ""))


class PortRegistryApp(App[None]):
    TITLE = "PortRegistry"
    SUB_TITLE = f"v{__version__}"
    CSS = """
    Screen { overflow: hidden; }
    TabbedContent { height: 1fr; }
    TabPane { height: 1fr; padding: 0 1; }
    #status { height: 1; padding: 0 1; background: $boost; }
    #status.offline { background: $error 40%; }
    #ports-search { margin: 0 0 1 0; }
    DataTable { height: 1fr; }
    #dashboard-body, #settings-body { padding: 1 2; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("slash", "search", "Search"),
        Binding("a", "add_service", "Add service"),
        Binding("n", "new_reservation", "New reservation"),
        Binding("x", "release", "Release", show=False),
        Binding("i", "toggle_info", "Info conflicts", show=False),
        Binding("z", "toggle_noise", "History noise", show=False),
        Binding("k", "mark_known", "Mark known", show=False),
        Binding("s", "adopt", "Register as service", show=False),
        Binding("X", "stop_process", "Stop process", show=False),
        Binding("question_mark", "help", "Help"),
        *[
            Binding(str(i + 1), f"show_tab('{tab}')", tab.title(), show=False)
            for i, tab in enumerate(TABS)
        ],
    ]

    def __init__(
        self,
        client_factory: Callable[[], Any] | None = None,
        *,
        live_updates: bool = True,
    ) -> None:
        super().__init__()
        self._client_factory = client_factory or AsyncApiClient.from_environment
        self.client: Any = None
        self._live_updates = live_updates
        self._data: dict[str, Any] = {}
        self._rows: dict[str, dict[str, Any]] = {}
        self._show_info = False
        self._show_noise = False
        self._refresh_pending = False
        self.connected = False

    # ---------------------------------------------------------------- layout

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Connecting to daemon…", id="status")
        with TabbedContent(initial="dashboard"):
            with TabPane("Dashboard", id="dashboard"), VerticalScroll():
                yield Static("Loading…", id="dashboard-body")
            with TabPane("Ports", id="ports"):
                yield Input(
                    placeholder="Search port, address, process, user, PID (Enter)",
                    id="ports-search",
                )
                yield DataTable(id="ports-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Services", id="services"):
                yield DataTable(id="services-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Reservations", id="reservations"):
                yield DataTable(id="reservations-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Conflicts", id="conflicts"):
                yield DataTable(id="conflicts-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Machines", id="machines"):
                yield DataTable(id="machines-table", cursor_type="row", zebra_stripes=True)
            with TabPane("History", id="history"):
                yield DataTable(id="history-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Settings", id="settings"), VerticalScroll():
                yield Static("Loading…", id="settings-body")
        yield Footer()

    def on_mount(self) -> None:
        self.client = self._client_factory()
        columns = {
            "ports-table": [
                "Proto",
                "Address",
                "Port",
                "Label",
                "State",
                "PID",
                "Process",
                "Project",
                "User",
                "Docker",
                "Note",
                "Since",
            ],
            "services-table": ["ID", "Name", "Category", "Expected executable", "Reservations"],
            "reservations-table": [
                "ID",
                "Endpoint",
                "Status",
                "Service",
                "Conflicts",
                "Description",
            ],
            "conflicts-table": ["Severity", "Certainty", "Type", "Endpoint", "Title"],
            "machines-table": ["Hostname", "UUID", "OS", "Arch", "Online", "Last seen"],
            "history-table": ["Time", "Type", "Severity", "Summary"],
        }
        for table_id, cols in columns.items():
            self.query_one(f"#{table_id}", DataTable).add_columns(*cols)
        self.refresh_data()
        if self._live_updates:
            self.listen_for_events()

    async def on_unmount(self) -> None:
        if self.client is not None and hasattr(self.client, "aclose"):
            await self.client.aclose()

    # --------------------------------------------------------------- loading

    def _set_status(self, text: str, *, offline: bool = False) -> None:
        status = self.query_one("#status", Static)
        status.update(Text(text))
        status.set_class(offline, "offline")

    @work(exclusive=True, group="refresh")
    async def refresh_data(self) -> None:
        client = self.client
        search = self.query_one("#ports-search", Input).value.strip()
        try:
            (
                status,
                ports,
                services,
                reservations,
                conflicts,
                machines,
                history,
            ) = await asyncio.gather(
                client.get("status/"),
                client.results("ports/", q=search or None, limit=1000),
                client.results("services/", limit=500),
                client.results("reservations/", status="all", limit=500),
                client.results(
                    "conflicts/", min_severity=None if self._show_info else "warning", limit=1000
                ),
                client.results("machines/"),
                client.results("history/", limit=200, noise="1" if self._show_noise else None),
            )
        except Exception as exc:
            self.connected = False
            self._set_status(
                f"Daemon unreachable: {format_error(exc)} - showing last known data.", offline=True
            )
            return
        self._data.update(status=status)
        self._fill_dashboard(status)
        self._fill_settings(status)
        self._fill("ports-table", ports, self._port_row)
        self._fill("services-table", services, self._service_row)
        self._fill("reservations-table", reservations, self._reservation_row)
        self._fill("conflicts-table", conflicts, self._conflict_row)
        self._fill("machines-table", machines, self._machine_row, key="uuid")
        self._fill("history-table", history, self._event_row)
        disc = status["discovery"]
        stale = " [STALE]" if disc["stale"] else ""
        docker = status["providers"]["docker"]["state"]
        live = "live" if self.connected else "polling"
        self._set_status(
            f"{status['machine']['hostname']} · last complete scan {ago(disc['last_success_at'])}{stale}"
            f" · Docker {docker} · {live} · refreshed {datetime.now():%H:%M:%S}",
            offline=bool(stale),
        )

    def _fill(
        self,
        table_id: str,
        items: list[dict[str, Any]],
        row: Callable[[dict[str, Any]], list[Any]],
        key: str = "id",
    ) -> None:
        table = self.query_one(f"#{table_id}", DataTable)
        cursor = table.cursor_row
        table.clear()
        for item in items:
            row_key = f"{table_id}:{item.get(key)}"
            self._rows[row_key] = item
            table.add_row(*row(item), key=row_key)
        if items:
            table.move_cursor(row=min(cursor, len(items) - 1))

    # ----------------------------------------------------------------- rows

    @staticmethod
    def _port_row(p: dict[str, Any]) -> list[Any]:
        proc = p.get("process") or {}
        docker = ", ".join(
            f"{m['container']['name']}->{m['container_port']}" for m in p.get("docker") or []
        )
        return [
            p["protocol"].upper(),
            plain(p["address"]),
            str(p["port"]),
            plain(p.get("label") or ""),
            p["state"],
            str(p.get("pid") or "-"),
            plain(proc.get("name") or ("unresolved" if p.get("pid") else "unknown")),
            plain(proc.get("project") or ""),
            plain(proc.get("username")),
            plain(docker or "-"),
            Text(str(p.get("ignored") or ""), style="dim"),
            ago(p.get("first_seen")),
        ]

    @staticmethod
    def _service_row(s: dict[str, Any]) -> list[Any]:
        return [
            str(s["id"]),
            plain(s["name"]),
            plain(s["category"]),
            plain(s["expected_executable"]),
            str(s.get("active_reservation_count", "-")),
        ]

    @staticmethod
    def _reservation_row(r: dict[str, Any]) -> list[Any]:
        conflicts = [c for c in r.get("conflicts", []) if c["severity"] != "info"]
        status = r.get("display_status", r["status"])
        return [
            str(r["id"]),
            plain(r["endpoint"]),
            styled(status, {"attention": "yellow", "active": "green", "released": "dim"}),
            plain((r.get("service") or {}).get("name")),
            plain(", ".join(sorted({c["type"] for c in conflicts})) or "-"),
            plain(r["description"]),
        ]

    @staticmethod
    def _conflict_row(c: dict[str, Any]) -> list[Any]:
        endpoint = f"{c['protocol']} {c['address'] or '*'}:{c['port']}" if c.get("port") else "-"
        return [
            styled(c["severity"], SEVERITY_STYLE),
            c["certainty"],
            c["type"],
            plain(endpoint),
            plain(c["title"]),
        ]

    @staticmethod
    def _machine_row(m: dict[str, Any]) -> list[Any]:
        return [
            plain(m["hostname"]),
            m["uuid"],
            plain(f"{m['os_name']} {m['os_version']}"),
            plain(m["architecture"]),
            "yes" if m["online"] else "no",
            ago(m.get("last_seen")),
        ]

    @staticmethod
    def _event_row(e: dict[str, Any]) -> list[Any]:
        return [
            e["timestamp"][:19].replace("T", " "),
            e["type"],
            styled(e["severity"], SEVERITY_STYLE),
            plain(e["summary"]),
        ]

    def _fill_dashboard(self, status: dict[str, Any]) -> None:
        s, disc, m = status["summary"], status["discovery"], status["machine"]
        e, r, c = s["endpoints"], s["reservations"], s["conflicts"]
        text = Text()
        text.append(f"{m['hostname']}  ", style="bold")
        text.append(f"{m['os_name']} {m['os_version']} · {m['uuid']}\n\n")
        text.append("Discovery   ", style="bold")
        text.append(f"last complete scan {ago(disc['last_success_at'])}")
        text.append(
            "  STALE\n" if disc["stale"] else "\n", style="bold red" if disc["stale"] else ""
        )
        for name, prov in status["providers"].items():
            text.append(f"  {name:<9} ")
            text.append(prov["state"], style=STATE_STYLE.get(prov["state"], ""))
            text.append(f"  {prov.get('message') or ''}\n")
        text.append("\nEndpoints   ", style="bold")
        text.append(
            f"{e['total']} ({e['tcp']} TCP / {e['udp']} UDP, {e['ipv4']} IPv4 / {e['ipv6']} IPv6)\n"
        )
        text.append("Processes   ", style="bold")
        text.append(f"{s['processes']} ({e['unresolved_owner']} endpoints with unknown owner)\n")
        text.append("Registry    ", style="bold")
        text.append(f"{s['services']} services, {r['active']} active reservations")
        text.append(
            f", {r['attention']} need attention\n" if r["attention"] else "\n",
            style="yellow" if r["attention"] else "",
        )
        text.append("Conflicts   ", style="bold")
        text.append(f"{c['error']} error", style="bold red")
        text.append(", ")
        text.append(f"{c['warning']} warning", style="yellow")
        text.append(", ")
        text.append(f"{c['info']} info\n", style="cyan")
        text.append("Containers  ", style="bold")
        text.append(f"{s['containers']['running']} running / {s['containers']['present']} known\n")
        platform = status.get("platform") or {}
        if platform.get("elevated") is False:
            text.append(
                "\nRunning without elevated privileges: some metadata may be hidden.\n", style="dim"
            )
        self.query_one("#dashboard-body", Static).update(text)

    def _fill_settings(self, status: dict[str, Any]) -> None:
        d, cfg = status["daemon"], status.get("config", {})
        text = Text()
        text.append("Daemon\n", style="bold")
        text.append(
            f"  version {d['version']}  pid {d['pid']}  {d['base_url']}  up {int(d['uptime_seconds'])}s\n"
        )
        text.append(
            "Configuration (read-only; edit config.toml and restart the daemon)\n", style="bold"
        )
        for key, value in cfg.items():
            text.append(f"  {key}: {value}\n")
        sched = status.get("scheduler") or {}
        if sched:
            text.append("Scheduler\n", style="bold")
            text.append(
                f"  next native scan in {sched.get('next_native_in')}s, job: {sched.get('current_job') or 'idle'}\n"
            )
        notes = (status.get("platform") or {}).get("notes") or []
        if notes:
            text.append("Platform notes\n", style="bold")
            for note in notes:
                text.append(f"  - {note}\n")
        self.query_one("#settings-body", Static).update(text)

    # ------------------------------------------------------------ live events

    def schedule_refresh(self) -> None:
        if self._refresh_pending:
            return
        self._refresh_pending = True

        def run() -> None:
            self._refresh_pending = False
            self.refresh_data()

        self.set_timer(0.5, run)

    @work(exclusive=True, group="sse")
    async def listen_for_events(self) -> None:
        backoff = 1.0
        while True:
            try:
                async for event, _data in self.client.stream_events():
                    if event == "hello":
                        self.connected = True
                        backoff = 1.0
                        self.schedule_refresh()
                    elif event == "daemon":
                        self.connected = False
                    elif event != "message":
                        self.schedule_refresh()
                raise ConnectionError("event stream closed")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.connected = False
                self._set_status(
                    f"Live updates disconnected ({format_error(exc)}); retrying in {int(backoff)}s. "
                    "Showing last known data.",
                    offline=True,
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)

    # ---------------------------------------------------------------- actions

    def action_refresh(self) -> None:
        self.refresh_data()

    def action_show_tab(self, tab: str) -> None:
        self.query_one(TabbedContent).active = tab

    def action_search(self) -> None:
        self.action_show_tab("ports")
        self.query_one("#ports-search", Input).focus()

    @on(Input.Submitted, "#ports-search")
    def _search_submitted(self) -> None:
        self.refresh_data()
        self.query_one("#ports-table", DataTable).focus()

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_toggle_noise(self) -> None:
        self._show_noise = not self._show_noise
        self.notify(
            "Showing short-lived/ignored history" if self._show_noise else "Hiding history noise"
        )
        self.refresh_data()

    def _selected_port(self) -> dict[str, Any] | None:
        if self.query_one(TabbedContent).active != "ports":
            self.notify("Select an endpoint on the Ports tab first.", severity="warning")
            return None
        item = self._selected("ports-table")
        if item is None:
            self.notify("No endpoint selected.", severity="warning")
        return item

    def action_mark_known(self) -> None:
        item = self._selected_port()
        if item is not None:
            self._mark_known(item["id"])

    @work
    async def _mark_known(self, socket_id: int) -> None:
        try:
            rule = await self.client.post(f"ports/{socket_id}/known/")
        except Exception as exc:
            self.notify(format_error(exc), severity="error")
            return
        self.notify(f"Added ignore rule '{rule['name']}'")
        self.refresh_data()

    def action_adopt(self) -> None:
        item = self._selected_port()
        if item is not None:
            self._adopt(item["id"])

    @work
    async def _adopt(self, socket_id: int) -> None:
        try:
            proposal = await self.client.get("services/adopt/", socket=socket_id)
        except Exception as exc:
            self.notify(format_error(exc), severity="error")
            return

        def done(result: dict[str, Any] | None) -> None:
            if result:
                self.notify(
                    f"Service '{result['service']['name']}' registered with "
                    f"{len(result['reservations'])} reservation(s)"
                )
                self.refresh_data()

        self.push_screen(AdoptScreen(self.client, proposal), done)

    def action_stop_process(self) -> None:
        item = self._selected_port()
        if item is None:
            return
        process = item.get("process") or {}
        if not process.get("id"):
            self.notify("The owner of this endpoint is unknown.", severity="warning")
            return
        self._stop_process(int(process["id"]))

    @work
    async def _stop_process(self, process_id: int) -> None:
        headers = control_headers("tui")
        try:
            preview = await self.client.request(
                "GET",
                f"processes/{process_id}/stop/preview/",
                params={"mode": "process"},
                headers=headers,
            )
        except Exception as exc:
            self.notify(format_error(exc), severity="error")
            return

        def done(op: dict[str, Any] | None) -> None:
            if not op:
                return
            outcome = op.get("outcome")
            severity = (
                "information"
                if outcome == "stopped"
                else ("warning" if outcome == "timeout" else "error")
            )
            self.notify(str(op.get("message") or outcome), severity=severity)
            self.refresh_data()

        self.push_screen(StopScreen(self.client, preview, headers), done)

    def action_toggle_info(self) -> None:
        self._show_info = not self._show_info
        self.notify(
            "Showing info-level conflicts" if self._show_info else "Hiding info-level conflicts"
        )
        self.refresh_data()

    def action_add_service(self) -> None:
        def done(result: dict[str, Any] | None) -> None:
            if result:
                self.notify(f"Service '{result['name']}' registered")
                self.refresh_data()

        self.push_screen(ServiceFormScreen(self.client), done)

    def action_new_reservation(self) -> None:
        port, protocol = None, "tcp"
        if self.query_one(TabbedContent).active == "ports":
            item = self._selected("ports-table")
            if item:
                port, protocol = item["port"], item["protocol"]

        def done(result: dict[str, Any] | None) -> None:
            if result:
                serious = [c for c in result.get("conflicts", []) if c["severity"] != "info"]
                msg = f"Reservation #{result['id']} created"
                self.notify(
                    msg + (f" with {len(serious)} conflict(s)" if serious else ""),
                    severity="warning" if serious else "information",
                )
                self.refresh_data()

        self.push_screen(ReservationFormScreen(self.client, port, protocol), done)

    def _selected(self, table_id: str) -> dict[str, Any] | None:
        table = self.query_one(f"#{table_id}", DataTable)
        if table.row_count == 0:
            return None
        try:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        except Exception:
            return None
        return self._rows.get(str(row_key.value))

    def action_release(self) -> None:
        if self.query_one(TabbedContent).active != "reservations":
            return
        item = self._selected("reservations-table")
        if not item or item["status"] != "active":
            self.notify("Select an active reservation to release.", severity="warning")
            return

        def confirmed(ok: bool | None) -> None:
            if ok:
                self._release(item["id"])

        self.push_screen(
            ConfirmScreen(f"Release reservation #{item['id']} ({item['endpoint']})?"), confirmed
        )

    @work
    async def _release(self, reservation_id: int) -> None:
        try:
            await self.client.post(f"reservations/{reservation_id}/release/")
        except Exception as exc:
            self.notify(format_error(exc), severity="error")
            return
        self.notify(f"Reservation #{reservation_id} released")
        self.refresh_data()

    @on(DataTable.RowSelected)
    def _row_selected(self, event: DataTable.RowSelected) -> None:
        key = str(event.row_key.value)
        item = self._rows.get(key)
        if item is None:
            return
        table_id = key.split(":", 1)[0]
        self.show_details(table_id, item)

    @work
    async def show_details(self, table_id: str, item: dict[str, Any]) -> None:
        detail_paths = {
            "ports-table": f"ports/{item.get('id')}/",
            "services-table": f"services/{item.get('id')}/",
            "reservations-table": f"reservations/{item.get('id')}/",
        }
        data: Any = item
        path = detail_paths.get(table_id)
        if path:
            try:
                data = await self.client.get(path)
            except Exception as exc:
                self.notify(format_error(exc), severity="error")
        title = (
            item.get("endpoint")
            or item.get("title")
            or item.get("name")
            or item.get("summary")
            or "Details"
        )
        self.push_screen(DetailScreen(str(title), data))


def run_tui() -> None:
    PortRegistryApp().run()
