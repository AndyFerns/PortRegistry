"""Modal screens: details, forms, confirmation and help."""

from __future__ import annotations

import asyncio
import json
import time
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


def assessment_text(data: dict[str, Any]) -> Text:
    """Plain-text rendering of a stop assessment (untrusted values never become markup)."""
    ident = data.get("identity") or {}
    target = data.get("target") or {}
    text = Text()

    def line(label: str, value: Any, style: str = "") -> None:
        text.append(f"{label:<14}", style="bold")
        text.append(str(value) if value not in (None, "") else "-", style=style)
        text.append("\n")

    line("Process", f"{ident.get('name') or '?'} (PID {ident.get('pid')})")
    cmdline = target.get("cmdline") or ident.get("cmdline") or []
    line("Command line", " ".join(cmdline))
    line("Folder", target.get("cwd") or ident.get("cwd"))
    line("User", target.get("username") or ident.get("username"))
    chain = " -> ".join(
        f"{p.get('name') or '?'} ({p.get('pid')})" for p in reversed(data.get("parent_chain") or [])
    )
    line("Started by", (chain + " -> this process") if chain else "unknown")
    line("Mode", "WHOLE TREE" if data.get("mode") == "tree" else "this process only")
    line("How", data.get("method_label"), "green" if data.get("graceful") else "yellow")
    impact = data.get("impact") or {}
    line("Ports freed", ", ".join(impact.get("ports") or []) or "none observed")
    if impact.get("services"):
        line("Services", "; ".join(impact["services"]), "yellow")
    members = data.get("members") or []
    if data.get("mode") == "tree" or len(members) > 1:
        text.append(f"Stop order ({len(members)} processes, children first):\n", style="bold")
        for m in members:
            flag = "  PROTECTED" if m.get("refusals") else ""
            text.append(
                f"  {'  ' * int(m.get('depth') or 0)}{m.get('name') or '?'} "
                f"(PID {m.get('pid')}, {m.get('method')}){flag}\n",
                style="red" if flag else "",
            )
    for w in data.get("warnings") or []:
        text.append(f"Note: {w}\n", style="yellow")
    for r in data.get("reasons") or []:
        text.append(f"Refused: {r}\n", style="red")
    for d in data.get("docker") or []:
        text.append(f"Use Docker: {d.get('command')}\n", style="bold")
    if data.get("commands"):
        text.append("Do it yourself instead:\n", style="bold")
        for c in data["commands"]:
            text.append(f"  {c.get('command')}   # {c.get('label')}\n")
    if data.get("command_note"):
        text.append(str(data["command_note"]) + "\n", style="dim")
    return text


class StopScreen(ModalScreen[dict[str, Any] | None]):
    """Two-step stop: Continue (gets a 30 s code), then type the PID and Stop."""

    DEFAULT_CSS = MODAL_CSS
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, client: Any, preview: dict[str, Any], headers: dict[str, str]) -> None:
        super().__init__()
        self._client = client
        self._data = preview
        self._headers = headers
        self._code: str | None = None
        self._expires_at = 0.0

    @property
    def target_pid(self) -> str:
        return str((self._data.get("identity") or {}).get("pid"))

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("", id="title", classes="title")
            with VerticalScroll(id="body"):
                yield Static("", id="assessment")
            with Horizontal(classes="buttons"):
                yield Button("Whole tree", id="mode")
                yield Button("Forced stop", id="force")
            yield Label("", id="step")
            yield Input(placeholder="Type the PID to confirm", id="pid", disabled=True)
            yield Label("", id="error", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Continue", variant="warning", id="continue")
                yield Button("Stop", variant="error", id="confirm", disabled=True)
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self._show()
        self.set_interval(1.0, self._tick)

    def _show(self) -> None:
        data = self._data
        ident = data.get("identity") or {}
        self.query_one("#title", Label).update(
            plain(f"Stop {ident.get('name') or '?'} (PID {ident.get('pid')})")
        )
        self.query_one("#assessment", Static).update(assessment_text(data))
        self.query_one("#mode", Button).label = (
            "This process only" if data.get("mode") == "tree" else "Whole tree"
        )
        self.query_one("#force", Button).label = (
            "Graceful stop" if data.get("force") else "Forced stop"
        )
        can = bool(data.get("can_request"))
        self.query_one("#continue", Button).disabled = not can or self._code is not None
        step = self.query_one("#step", Label)
        if not data.get("control_enabled"):
            step.update(plain(data.get("control", {}).get("reason") or "Process control is off."))
        elif not can:
            step.update(plain("PortRegistry will not stop this process (see above)."))
        elif self._code is None:
            step.update(plain("Step 1 of 2: Continue to get a 30-second confirmation."))

    def _reset_code(self) -> None:
        self._code = None
        pid_input = self.query_one("#pid", Input)
        pid_input.value = ""
        pid_input.disabled = True
        self.query_one("#confirm", Button).disabled = True

    def _tick(self) -> None:
        if self._code is None:
            return
        remaining = int(self._expires_at - time.monotonic())
        if remaining <= 0:
            self._reset_code()
            self._show()
            self.query_one("#step", Label).update(
                plain("The confirmation expired. Press Continue to review again.")
            )
            return
        self.query_one("#step", Label).update(
            plain(
                f"Step 2 of 2: type the PID {self.target_pid} and press Stop ({remaining}s left)."
            )
        )

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#mode")
    def _toggle_mode(self) -> None:
        self._reload(
            mode="process" if self._data.get("mode") == "tree" else "tree",
            force=bool(self._data.get("force")),
        )

    @on(Button.Pressed, "#force")
    def _toggle_force(self) -> None:
        self._reload(
            mode=str(self._data.get("mode") or "process"), force=not self._data.get("force")
        )

    @work(exclusive=True)
    async def _reload(self, *, mode: str, force: bool) -> None:
        self._reset_code()
        try:
            self._data = await self._client.request(
                "GET",
                f"processes/{self._data['process_id']}/stop/preview/",
                params={"mode": mode, "force": "1" if force else ""},
                headers=self._headers,
            )
        except Exception as exc:
            self.query_one("#error", Label).update(plain(format_error(exc)))
            return
        self.query_one("#error", Label).update("")
        self._show()

    @on(Button.Pressed, "#continue")
    def _continue(self) -> None:
        self.request_code()

    @work(exclusive=True)
    async def request_code(self) -> None:
        try:
            issued = await self._client.post(
                f"processes/{self._data['process_id']}/stop/request/",
                {"mode": self._data.get("mode"), "force": bool(self._data.get("force"))},
                headers=self._headers,
            )
        except Exception as exc:
            self.query_one("#error", Label).update(
                plain("Nothing was stopped: " + format_error(exc))
            )
            return
        self._data = issued["assessment"]
        self._code = issued["code"]
        self._expires_at = time.monotonic() + float(issued["expires_in"])
        self.query_one("#error", Label).update("")
        self._show()
        self._tick()
        pid_input = self.query_one("#pid", Input)
        pid_input.disabled = False
        pid_input.focus()

    @on(Input.Changed, "#pid")
    def _pid_changed(self, event: Input.Changed) -> None:
        matches = self._code is not None and event.value.strip() == self.target_pid
        self.query_one("#confirm", Button).disabled = not matches

    @on(Input.Submitted, "#pid")
    def _pid_submitted(self) -> None:
        if not self.query_one("#confirm", Button).disabled:
            self.confirm()

    @on(Button.Pressed, "#confirm")
    def _confirm(self) -> None:
        self.confirm()

    @work(exclusive=True)
    async def confirm(self) -> None:
        code, self._code = self._code, None
        if code is None:
            return
        self.query_one("#confirm", Button).disabled = True
        self.query_one("#step", Label).update(plain("Stopping..."))
        try:
            op = await self._client.post(
                "processes/stop/confirm/",
                {"code": code, "pid": self.query_one("#pid", Input).value.strip()},
                headers=self._headers,
                timeout=30,
            )
            deadline = time.monotonic() + float(op.get("grace_seconds") or 10) + 20
            while op.get("state") == "running" and time.monotonic() < deadline:
                await asyncio.sleep(0.5)
                op = await self._client.get(f"processes/stop/operations/{op['id']}/")
        except Exception as exc:
            self._reset_code()
            self.query_one("#error", Label).update(
                plain("Nothing was stopped: " + format_error(exc))
            )
            self._show()
            return
        self.dismiss(op)


HELP_TEXT = """\
PortRegistry TUI - all data comes from the local daemon.

  q        quit                     r        refresh now
  /        search ports             Tab      move focus
  Enter    details for the row      Esc      back / close dialog
  a        add service              n        new reservation
  x        release reservation      i        toggle info-level conflicts
  s        register endpoint as a service (Ports tab)
  k        mark endpoint as known (Ports tab)
  X        stop the owning process (Ports tab; opt-in, two-step)
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
