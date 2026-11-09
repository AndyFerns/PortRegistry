"""Modal screens: details, forms, confirmation and help."""

from __future__ import annotations

import json
from typing import Any

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Static

from portregistry.exceptions import ApiError, PortRegistryError

MODAL_CSS = """
ModalScreen { align: center middle; }
#dialog {
    width: 90%; max-width: 110; height: auto; max-height: 90%;
    border: thick $accent; background: $surface; padding: 1 2;
}
#dialog Input, #dialog Select { margin-bottom: 1; }
#dialog .title { text-style: bold; margin-bottom: 1; }
#dialog .error { color: $error; }
#dialog .buttons { height: auto; margin-top: 1; }
#dialog Button { margin-right: 2; }
#body { height: auto; max-height: 30; }
"""


def plain(value: Any) -> Text:
    """Untrusted values must never be interpreted as markup."""
    if value is None or value == "":
        return Text("-")
    return Text(str(value))


def format_error(exc: Exception) -> str:
    if isinstance(exc, ApiError):
        fields = exc.details.get("fields") if isinstance(exc.details, dict) else None
        if isinstance(fields, dict) and fields:
            parts = [
                f"{k}: {'; '.join(v) if isinstance(v, list) else v}" for k, v in fields.items()
            ]
            return f"{exc.message} " + " | ".join(parts)
        return exc.message
    if isinstance(exc, PortRegistryError):
        return exc.message
    return str(exc)


class DetailScreen(ModalScreen[None]):
    """Read-only details for any row (Esc to close)."""

    DEFAULT_CSS = MODAL_CSS
    BINDINGS = [Binding("escape", "dismiss", "Back"), Binding("q", "dismiss", "Back", show=False)]

    def __init__(self, title: str, data: Any) -> None:
        super().__init__()
        self._title = title
        self._data = data

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(plain(self._title), classes="title")
            with VerticalScroll(id="body"):
                yield Static(plain(json.dumps(self._data, indent=2, default=str)))
            yield Label("Esc to close", classes="hint")


class ConfirmScreen(ModalScreen[bool]):
    DEFAULT_CSS = MODAL_CSS
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, question: str) -> None:
        super().__init__()
        self._question = question

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(plain(self._question), classes="title")
            with Horizontal(classes="buttons"):
                yield Button("Confirm", variant="error", id="confirm")
                yield Button("Cancel", id="cancel")

    @on(Button.Pressed, "#confirm")
    def _confirm(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(False)


class ServiceFormScreen(ModalScreen[dict[str, Any] | None]):
    """Register a service via the daemon API."""

    DEFAULT_CSS = MODAL_CSS
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, client: Any) -> None:
        super().__init__()
        self._client = client

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("Register service", classes="title")
            yield Input(placeholder="Name (required)", id="name")
            yield Input(
                placeholder="Expected executable (e.g. postgres, /usr/bin/node, docker:web)",
                id="exe",
            )
            yield Input(placeholder="Expected working directory", id="cwd")
            yield Input(placeholder="Category (database, web, dev-tool...)", id="category")
            yield Input(placeholder="Description", id="description")
            yield Label("", id="error", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Save", variant="primary", id="save")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#name", Input).focus()

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#save")
    @on(Input.Submitted)
    def _save(self) -> None:
        self.save()

    @work(exclusive=True)
    async def save(self) -> None:
        values = {
            "name": self.query_one("#name", Input).value.strip(),
            "expected_executable": self.query_one("#exe", Input).value.strip(),
            "expected_working_directory": self.query_one("#cwd", Input).value.strip(),
            "category": self.query_one("#category", Input).value.strip(),
            "description": self.query_one("#description", Input).value.strip(),
        }
        try:
            created = await self._client.post("services/", values)
        except Exception as exc:
            self.query_one("#error", Label).update(plain(format_error(exc)))
            return
        self.dismiss(created)


class ReservationFormScreen(ModalScreen[dict[str, Any] | None]):
    """Create an advisory reservation, with a dry-run availability check."""

    DEFAULT_CSS = MODAL_CSS
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, client: Any, port: int | None = None, protocol: str = "tcp") -> None:
        super().__init__()
        self._client = client
        self._port = port
        self._protocol = protocol

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("New reservation (advisory: does not bind the port)", classes="title")
            yield Input(value=str(self._port or ""), placeholder="Port (1-65535)", id="port")
            yield Select(
                [("TCP", "tcp"), ("UDP", "udp")],
                value=self._protocol,
                allow_blank=False,
                id="protocol",
            )
            yield Input(value="*", placeholder="Bind address (* = any)", id="address")
            yield Input(placeholder="Service name or id (optional)", id="service")
            yield Input(placeholder="Description", id="description")
            yield Static("", id="findings")
            yield Label("", id="error", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Suggest free port", id="suggest")
                yield Button("Check", id="check")
                yield Button("Save", variant="primary", id="save")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#port", Input).focus()

    def _payload(self) -> dict[str, Any]:
        port_text = self.query_one("#port", Input).value.strip()
        payload: dict[str, Any] = {
            "port": int(port_text) if port_text.isdigit() else port_text,
            "protocol": self.query_one("#protocol", Select).value,
            "bind_address": self.query_one("#address", Input).value.strip() or "*",
            "description": self.query_one("#description", Input).value.strip(),
        }
        service = self.query_one("#service", Input).value.strip()
        if service:
            payload["service"] = service
        return payload

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#suggest")
    def _suggest(self) -> None:
        self.suggest()

    @work(exclusive=True)
    async def suggest(self) -> None:
        protocol = self.query_one("#protocol", Select).value
        address = self.query_one("#address", Input).value.strip() or "*"
        try:
            data = await self._client.get(
                "ports/free/", protocol=protocol, address=address, count=1
            )
        except Exception as exc:
            self.query_one("#error", Label).update(plain(format_error(exc)))
            return
        if not data.get("ports"):
            self.query_one("#error", Label).update("No free port found in 3000-9999.")
            return
        self.query_one("#port", Input).value = str(data["ports"][0]["port"])
        self.check()

    @on(Button.Pressed, "#check")
    def _check(self) -> None:
        self.check()

    @on(Button.Pressed, "#save")
    def _save(self) -> None:
        self.save()

    def _show_findings(self, findings: list[dict[str, Any]]) -> None:
        text = Text()
        if not findings:
            text.append("No current occupant or overlapping reservation.", style="green")
        for f in findings:
            style = {"error": "bold red", "warning": "yellow"}.get(f["severity"], "cyan")
            text.append(f"{f['severity']} ({f['certainty']}) ", style=style)
            text.append(f"{f['title']}\n", style="bold")
            text.append(f"  {f['explanation']}\n")
        self.query_one("#findings", Static).update(text)

    @work(exclusive=True)
    async def check(self) -> None:
        self.query_one("#error", Label).update("")
        payload = {k: v for k, v in self._payload().items() if k != "description"}
        try:
            data = await self._client.post("reservations/check/", payload)
        except Exception as exc:
            self.query_one("#error", Label).update(plain(format_error(exc)))
            return
        self._show_findings(data.get("findings", []))

    @work(exclusive=True)
    async def save(self) -> None:
        try:
            created = await self._client.post("reservations/", self._payload())
        except Exception as exc:
            self.query_one("#error", Label).update(plain(format_error(exc)))
            return
        self.dismiss(created)


class AdoptScreen(ModalScreen[dict[str, Any] | None]):
    """Register an observed endpoint's process as a service (pre-filled)."""

    DEFAULT_CSS = MODAL_CSS
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, client: Any, proposal: dict[str, Any]) -> None:
        super().__init__()
        self._client = client
        self._proposal = proposal

    def compose(self) -> ComposeResult:
        svc = self._proposal["service"]
        selected = [e for e in self._proposal["endpoints"] if e["selected"]]
        with Vertical(id="dialog"):
            yield Label(plain(f"Register as service: {self._proposal['source']}"), classes="title")
            yield Input(value=svc["name"], placeholder="Name", id="name")
            yield Input(
                value=svc["expected_executable"], placeholder="Expected executable", id="exe"
            )
            yield Input(
                value=svc["expected_working_directory"], placeholder="Working directory", id="cwd"
            )
            yield Input(value=svc["category"], placeholder="Category", id="category")
            yield Static(
                plain("Reserves: " + (", ".join(e["endpoint"] for e in selected) or "nothing"))
            )
            yield Label("", id="error", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Save", variant="primary", id="save")
                yield Button("Cancel", id="cancel")

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#save")
    def _save(self) -> None:
        self.save()

    @work(exclusive=True)
    async def save(self) -> None:
        service = dict(self._proposal["service"])
        service.update(
            name=self.query_one("#name", Input).value.strip(),
            expected_executable=self.query_one("#exe", Input).value.strip(),
            expected_working_directory=self.query_one("#cwd", Input).value.strip(),
            category=self.query_one("#category", Input).value.strip(),
        )
        ids = [e["socket_id"] for e in self._proposal["endpoints"] if e["selected"]]
        try:
            result = await self._client.post(
                "services/adopt/", {"service": service, "socket_ids": ids}
            )
        except Exception as exc:
            self.query_one("#error", Label).update(plain(format_error(exc)))
            return
        self.dismiss(result)


HELP_TEXT = """\
PortRegistry TUI - all data comes from the local daemon.

  q        quit                     r        refresh now
  /        search ports             Tab      move focus
  Enter    details for the row      Esc      back / close dialog
  a        add service              n        new reservation
  x        release reservation      i        toggle info-level conflicts
  s        register endpoint as a service (Ports tab)
  k        mark endpoint as known (Ports tab)
  z        show/hide short-lived history noise
  1-8      switch tabs              ?        this help

Live updates arrive over Server-Sent Events; if the connection drops the
TUI keeps the last data, shows a warning, and reconnects automatically.
Reservations are advisory: they never bind ports.
"""


class HelpScreen(ModalScreen[None]):
    DEFAULT_CSS = MODAL_CSS
    BINDINGS = [Binding("escape", "dismiss", "Back"), Binding("question_mark", "dismiss", "Back")]

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("Help", classes="title")
            yield Static(Text(HELP_TEXT))
