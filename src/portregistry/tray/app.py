"""PortRegistry tray icon.

A thin client of the daemon API: it never touches the database or runs
discovery. All behaviour lives in :class:`TrayController` (unit-testable);
:func:`run_tray` only wires it to pystray/Pillow, which come from the optional
``portregistry[tray]`` extra.

Notifications use pystray where the platform backend supports them, then
``notify-send`` (Linux) or ``osascript`` (macOS). Notification text is always
passed as process arguments, never interpolated into a shell or script.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from collections.abc import Callable
from typing import Any

from portregistry.client import ApiClient
from portregistry.exceptions import PortRegistryError

logger = logging.getLogger(__name__)

STATE_COLORS = {
    "ok": (46, 160, 67),
    "warning": (219, 161, 31),
    "error": (207, 34, 46),
    "offline": (120, 120, 120),
}
REFRESH_SECONDS = 30.0

Notifier = Callable[[str, str], None]


def state_from_status(status: dict[str, Any] | None) -> tuple[str, str]:
    """(state, tooltip) for a daemon status payload (None = unreachable)."""
    if status is None:
        return "offline", "PortRegistry: daemon not running"
    c = status["summary"]["conflicts"]
    e = status["summary"]["endpoints"]
    stale = status["discovery"].get("stale")
    if c["error"]:
        state = "error"
    elif c["warning"] or stale:
        state = "warning"
    else:
        state = "ok"
    tip = f"PortRegistry: {e['total']} endpoints, {c['error']} errors, {c['warning']} warnings"
    if stale:
        tip += " (data stale)"
    return state, tip[:120]


def alert_text(event: dict[str, Any]) -> tuple[str, str]:
    data = event.get("data", event)
    kind = event.get("type", "")
    title = {
        "conflict.detected": "Port conflict",
        "conflict.resolved": "Conflict resolved",
        "docker.unavailable": "Docker unavailable",
        "docker.available": "Docker available",
        "scan.failed": "Discovery failed",
    }.get(kind, "PortRegistry")
    return title, str(data.get("summary") or kind)[:240]


class TrayController:
    def __init__(
        self,
        client_factory: Callable[[], ApiClient] = ApiClient.from_environment,
        notifier: Notifier | None = None,
        opener: Callable[[str], Any] = webbrowser.open,
        control: Any = None,
    ) -> None:
        self.client_factory = client_factory
        self.notifier = notifier
        self.opener = opener
        if control is None:
            from portregistry.daemon import control as control_module

            control = control_module
        self.control = control
        self.notifications = True
        self.state = "offline"
        self.tooltip = "PortRegistry"
        self.status: dict[str, Any] | None = None
        self.on_change: Callable[[], None] | None = None

    # ------------------------------------------------------------ state

    def refresh(self) -> str:
        try:
            with self.client_factory() as client:
                status = client.get("status/")
        except PortRegistryError:
            status = None
        self.status = status
        new_state, self.tooltip = state_from_status(status)
        changed = new_state != self.state
        self.state = new_state
        if self.on_change:
            self.on_change()
        return "changed" if changed else "same"

    def handle_event(self, event: str, data: dict[str, Any]) -> None:
        if event == "alerts" and self.notifications and self.notifier:
            title, message = alert_text(data)
            try:
                self.notifier(title, message)
            except Exception:
                logger.debug("Notification failed", exc_info=True)
        if event in ("alerts", "conflicts", "scan", "docker", "hello"):
            self.refresh()

    @property
    def conflict_label(self) -> str:
        if not self.status:
            return "Conflicts: unavailable"
        c = self.status["summary"]["conflicts"]
        return f"Conflicts: {c['error']} error, {c['warning']} warning"

    # ---------------------------------------------------------- actions

    def open_gui(self, path: str = "/") -> None:
        try:
            with self.client_factory() as client:
                link = client.post("auth/gui-link/")["url"]
        except PortRegistryError as exc:
            self._notify("PortRegistry", exc.message)
            return
        if path != "/":
            # Log in via the single-use link first, then the browser can open the page.
            self.opener(link)
            base = link.split("/login/", 1)[0]
            self.opener(base + path)
        else:
            self.opener(link)

    def scan_now(self) -> None:
        try:
            with self.client_factory() as client:
                client.post("discovery/scan/", {})
        except PortRegistryError as exc:
            self._notify("PortRegistry", exc.message)

    def start_daemon(self) -> None:
        try:
            self.control.start_daemon()
        except PortRegistryError as exc:
            self._notify("PortRegistry", exc.message)
        self.refresh()

    def stop_daemon(self) -> None:
        try:
            self.control.stop_daemon()
        except PortRegistryError as exc:
            self._notify("PortRegistry", exc.message)
        self.refresh()

    def toggle_notifications(self) -> None:
        self.notifications = not self.notifications

    def _notify(self, title: str, message: str) -> None:
        if self.notifier:
            try:
                self.notifier(title, message)
            except Exception:
                logger.debug("Notification failed", exc_info=True)

    # ------------------------------------------------------ background

    def listen(self, stop: threading.Event) -> None:
        """SSE loop with reconnect; also refreshes periodically."""
        backoff = 1.0
        while not stop.is_set():
            try:
                with self.client_factory() as client:
                    for event, data in client.stream_events(read_timeout=REFRESH_SECONDS + 20):
                        if stop.is_set():
                            return
                        backoff = 1.0
                        self.handle_event(event, data)
            except Exception:
                self.refresh()
                stop.wait(backoff)
                backoff = min(backoff * 2, 30.0)


def system_notifier(icon: Any) -> Notifier:
    def notify(title: str, message: str) -> None:
        if getattr(icon, "HAS_NOTIFICATION", False):
            icon.notify(message, title)
        elif sys.platform == "darwin" and shutil.which("osascript"):
            script = "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run"
            subprocess.run(["osascript", "-e", script, title, message], check=False, timeout=10)
        elif shutil.which("notify-send"):
            subprocess.run(
                ["notify-send", "--app-name=PortRegistry", title, message], check=False, timeout=10
            )

    return notify


def make_icon_image(state: str) -> Any:
    from PIL import Image, ImageDraw

    size = 64
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse(
        (6, 6, size - 6, size - 6), fill=(*STATE_COLORS.get(state, STATE_COLORS["offline"]), 255)
    )
    draw.ellipse((22, 22, size - 22, size - 22), fill=(255, 255, 255, 230))
    return image


def run_tray() -> None:
    try:
        import pystray
    except ImportError as exc:
        raise PortRegistryError(
            'The tray icon needs the optional extra: pip install "portregistry[tray]"'
        ) from exc

    controller = TrayController()
    stop = threading.Event()

    def quit_tray(icon_ref: Any) -> None:
        stop.set()
        icon_ref.stop()

    def menu() -> Any:
        item = pystray.MenuItem
        return pystray.Menu(
            item(lambda _: controller.tooltip, None, enabled=False),
            item("Open PortRegistry", lambda: controller.open_gui(), default=True),
            item(lambda _: controller.conflict_label, lambda: controller.open_gui("/conflicts/")),
            item("Scan now", lambda: controller.scan_now()),
            pystray.Menu.SEPARATOR,
            item(
                "Start daemon",
                lambda: controller.start_daemon(),
                visible=lambda _: controller.state == "offline",
            ),
            item(
                "Stop daemon",
                lambda: controller.stop_daemon(),
                visible=lambda _: controller.state != "offline",
            ),
            item(
                "Notifications",
                lambda: controller.toggle_notifications(),
                checked=lambda _: controller.notifications,
            ),
            pystray.Menu.SEPARATOR,
            item("Quit tray", quit_tray),
        )

    icon = pystray.Icon("portregistry", make_icon_image("offline"), "PortRegistry", menu())
    controller.notifier = system_notifier(icon)

    def redraw() -> None:
        icon.icon = make_icon_image(controller.state)
        icon.title = controller.tooltip
        try:
            icon.update_menu()
        except Exception:
            pass

    controller.on_change = redraw

    def background(_icon: Any) -> None:
        _icon.visible = True
        controller.refresh()
        threading.Thread(
            target=controller.listen, args=(stop,), daemon=True, name="pr-tray-sse"
        ).start()
        while not stop.is_set():
            stop.wait(REFRESH_SECONDS)
            controller.refresh()

    try:
        icon.run(setup=background)
    finally:
        stop.set()
        time.sleep(0.1)
