"""Start the PortRegistry daemon (and optionally the tray) at login.

Per-user mechanisms only; none need administrator rights:

* Windows: ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`` values
  launching ``pythonw -m portregistry daemon run --quiet`` (no console window).
  (A Scheduled Task with an ONLOGON trigger needs admin rights, so it is not used.)
* Linux: a systemd *user* unit (``systemctl --user enable --now``); without
  systemd, an XDG autostart ``.desktop`` file.
* macOS: a LaunchAgent plist loaded with ``launchctl bootstrap gui/<uid>``.

Every backend can describe its actions without performing them (``--dry-run``).
The daemon's own single-instance lock makes a duplicate start at login harmless.
"""

from __future__ import annotations

import os
import plistlib
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from portregistry.daemon.control import cli_command

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
WIN_DAEMON_VALUE = "PortRegistry"
WIN_TRAY_VALUE = "PortRegistryTray"
SYSTEMD_UNIT = "portregistry.service"
SYSTEMD_TRAY_UNIT = "portregistry-tray.service"
LAUNCHD_LABEL = "io.portregistry.daemon"
LAUNCHD_TRAY_LABEL = "io.portregistry.tray"


@dataclass
class Action:
    kind: str  # write_file | remove_file | set_registry | delete_registry | run
    target: str
    content: str = ""

    def describe(self) -> str:
        if self.kind == "write_file":
            return f"write {self.target}:\n{self.content}"
        if self.kind == "remove_file":
            return f"remove {self.target}"
        if self.kind == "set_registry":
            return f"set HKCU\\{RUN_KEY}\\{self.target} = {self.content}"
        if self.kind == "delete_registry":
            return f"delete HKCU\\{RUN_KEY}\\{self.target}"
        return f"run: {self.target}"


@dataclass
class AutostartStatus:
    mechanism: str
    installed: bool
    tray_installed: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "mechanism": self.mechanism,
            "installed": self.installed,
            "tray_installed": self.tray_installed,
            "details": self.details,
        }


def daemon_args(home: str | None) -> list[str]:
    args = [*cli_command(windowless=True), "daemon", "run", "--quiet"]
    if home:
        args += ["--home", home]
    return args


def tray_args(home: str | None) -> list[str]:
    args = [*cli_command(windowless=True), "tray"]
    if home:
        args += ["--home", home]
    return args


def _win_quote(args: list[str]) -> str:
    return subprocess.list2cmdline(args)


# --------------------------------------------------------------------- backends


class Backend(Protocol):
    mechanism: str

    def plan_install(self, home: str | None, tray: bool) -> list[Action]: ...

    def plan_uninstall(self) -> list[Action]: ...

    def status(self) -> AutostartStatus: ...

    def execute(self, actions: list[Action]) -> None: ...


class RegistryAdapter(Protocol):
    def get(self, name: str) -> str | None: ...

    def set(self, name: str, value: str) -> None: ...

    def delete(self, name: str) -> None: ...


class WinRegRun:
    """Real HKCU Run key access (Windows only)."""

    def get(self, name: str) -> str | None:
        if sys.platform != "win32":  # narrows the type for mypy on other platforms
            raise OSError("the Windows registry is only available on Windows")
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return str(value)
        except FileNotFoundError:
            return None

    def set(self, name: str, value: str) -> None:
        if sys.platform != "win32":  # narrows the type for mypy on other platforms
            raise OSError("the Windows registry is only available on Windows")
        import winreg

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)

    def delete(self, name: str) -> None:
        if sys.platform != "win32":  # narrows the type for mypy on other platforms
            raise OSError("the Windows registry is only available on Windows")
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass


class WindowsBackend:
    mechanism = "windows-run-key"

    def __init__(self, registry: RegistryAdapter | None = None) -> None:
        self.registry = registry or WinRegRun()

    def plan_install(self, home: str | None, tray: bool) -> list[Action]:
        actions = [Action("set_registry", WIN_DAEMON_VALUE, _win_quote(daemon_args(home)))]
        if tray:
            actions.append(Action("set_registry", WIN_TRAY_VALUE, _win_quote(tray_args(home))))
        return actions

    def plan_uninstall(self) -> list[Action]:
        return [
            Action("delete_registry", WIN_DAEMON_VALUE),
            Action("delete_registry", WIN_TRAY_VALUE),
        ]

    def status(self) -> AutostartStatus:
        daemon = self.registry.get(WIN_DAEMON_VALUE)
        tray = self.registry.get(WIN_TRAY_VALUE)
        return AutostartStatus(
            self.mechanism,
            daemon is not None,
            tray is not None,
            {"daemon_command": daemon, "tray_command": tray},
        )

    def execute(self, actions: list[Action]) -> None:
        for action in actions:
            if action.kind == "set_registry":
                self.registry.set(action.target, action.content)
            elif action.kind == "delete_registry":
                self.registry.delete(action.target)


Runner = Callable[[list[str]], int]


def _default_runner(args: list[str]) -> int:
    return subprocess.run(args, check=False, capture_output=True, timeout=30).returncode


class FileBackendBase:
    mechanism = "files"

    def __init__(self, base: Path | None = None, runner: Runner | None = None) -> None:
        self.base = base
        self.runner = runner or _default_runner

    def execute(self, actions: list[Action]) -> None:
        for action in actions:
            if action.kind == "write_file":
                path = Path(action.target)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(action.content, encoding="utf-8")
            elif action.kind == "remove_file":
                try:
                    Path(action.target).unlink()
                except FileNotFoundError:
                    pass
            elif action.kind == "run":
                code = self.runner(shlex.split(action.target))
                if code != 0:
                    raise RuntimeError(f"Command failed ({code}): {action.target}")


class SystemdBackend(FileBackendBase):
    mechanism = "systemd-user"

    def unit_dir(self) -> Path:
        if self.base is not None:
            return self.base
        config_home = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
        return Path(config_home) / "systemd" / "user"

    @staticmethod
    def unit(description: str, args: list[str], home: str | None, restart: bool) -> str:
        lines = [
            "[Unit]",
            f"Description={description}",
            "After=network.target",
            "",
            "[Service]",
            "Type=simple",
            f"ExecStart={shlex.join(args)}",
        ]
        if home:
            lines.append(f"Environment=PORTREGISTRY_HOME={home}")
        if restart:
            lines += ["Restart=on-failure", "RestartSec=5"]
        lines += ["", "[Install]", "WantedBy=default.target", ""]
        return "\n".join(lines)

    def plan_install(self, home: str | None, tray: bool) -> list[Action]:
        d = self.unit_dir()
        actions = [
            Action(
                "write_file",
                str(d / SYSTEMD_UNIT),
                self.unit("PortRegistry daemon", daemon_args(home), home, restart=True),
            ),
        ]
        units = [SYSTEMD_UNIT]
        if tray:
            actions.append(
                Action(
                    "write_file",
                    str(d / SYSTEMD_TRAY_UNIT),
                    self.unit("PortRegistry tray", tray_args(home), home, restart=False).replace(
                        "WantedBy=default.target", "WantedBy=graphical-session.target"
                    ),
                )
            )
            units.append(SYSTEMD_TRAY_UNIT)
        actions.append(Action("run", "systemctl --user daemon-reload"))
        actions.append(Action("run", "systemctl --user enable --now " + " ".join(units)))
        return actions

    def plan_uninstall(self) -> list[Action]:
        d = self.unit_dir()
        return [
            Action("run", f"systemctl --user disable --now {SYSTEMD_UNIT} {SYSTEMD_TRAY_UNIT}"),
            Action("remove_file", str(d / SYSTEMD_UNIT)),
            Action("remove_file", str(d / SYSTEMD_TRAY_UNIT)),
            Action("run", "systemctl --user daemon-reload"),
        ]

    def status(self) -> AutostartStatus:
        d = self.unit_dir()
        return AutostartStatus(
            self.mechanism,
            (d / SYSTEMD_UNIT).exists(),
            (d / SYSTEMD_TRAY_UNIT).exists(),
            {"unit_dir": str(d)},
        )

    def execute(self, actions: list[Action]) -> None:
        # `disable` of a unit that does not exist fails harmlessly during uninstall.
        for action in actions:
            if action.kind == "run" and "disable" in action.target:
                self.runner(shlex.split(action.target))
                continue
            super().execute([action])


class XdgAutostartBackend(FileBackendBase):
    mechanism = "xdg-autostart"

    def dir(self) -> Path:
        if self.base is not None:
            return self.base
        config_home = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
        return Path(config_home) / "autostart"

    @staticmethod
    def entry(name: str, args: list[str]) -> str:
        return "\n".join(
            [
                "[Desktop Entry]",
                "Type=Application",
                f"Name={name}",
                f"Exec={shlex.join(args)}",
                "X-GNOME-Autostart-enabled=true",
                "NoDisplay=true",
                "",
            ]
        )

    def plan_install(self, home: str | None, tray: bool) -> list[Action]:
        actions = [
            Action(
                "write_file",
                str(self.dir() / "portregistry.desktop"),
                self.entry("PortRegistry daemon", daemon_args(home)),
            )
        ]
        if tray:
            actions.append(
                Action(
                    "write_file",
                    str(self.dir() / "portregistry-tray.desktop"),
                    self.entry("PortRegistry tray", tray_args(home)),
                )
            )
        return actions

    def plan_uninstall(self) -> list[Action]:
        return [
            Action("remove_file", str(self.dir() / "portregistry.desktop")),
            Action("remove_file", str(self.dir() / "portregistry-tray.desktop")),
        ]

    def status(self) -> AutostartStatus:
        return AutostartStatus(
            self.mechanism,
            (self.dir() / "portregistry.desktop").exists(),
            (self.dir() / "portregistry-tray.desktop").exists(),
            {"dir": str(self.dir())},
        )


class LaunchdBackend(FileBackendBase):
    mechanism = "launchd"

    def dir(self) -> Path:
        return self.base if self.base is not None else Path.home() / "Library" / "LaunchAgents"

    @staticmethod
    def plist(label: str, args: list[str], home: str | None, keep_alive: bool) -> str:
        data: dict[str, Any] = {
            "Label": label,
            "ProgramArguments": args,
            "RunAtLoad": True,
            "ProcessType": "Background",
        }
        if keep_alive:
            data["KeepAlive"] = {"SuccessfulExit": False}
        if home:
            data["EnvironmentVariables"] = {"PORTREGISTRY_HOME": home}
        return plistlib.dumps(data).decode("utf-8")

    def _uid(self) -> int:
        return os.getuid() if hasattr(os, "getuid") else 0

    def plan_install(self, home: str | None, tray: bool) -> list[Action]:
        d = self.dir()
        uid = self._uid()
        daemon_plist = d / f"{LAUNCHD_LABEL}.plist"
        actions = [
            Action(
                "write_file",
                str(daemon_plist),
                self.plist(LAUNCHD_LABEL, daemon_args(home), home, True),
            ),
            Action("run", f"launchctl bootstrap gui/{uid} {shlex.quote(str(daemon_plist))}"),
        ]
        if tray:
            tray_plist = d / f"{LAUNCHD_TRAY_LABEL}.plist"
            actions += [
                Action(
                    "write_file",
                    str(tray_plist),
                    self.plist(LAUNCHD_TRAY_LABEL, tray_args(home), home, False),
                ),
                Action("run", f"launchctl bootstrap gui/{uid} {shlex.quote(str(tray_plist))}"),
            ]
        return actions

    def plan_uninstall(self) -> list[Action]:
        d = self.dir()
        uid = self._uid()
        return [
            Action("run", f"launchctl bootout gui/{uid}/{LAUNCHD_LABEL}"),
            Action("run", f"launchctl bootout gui/{uid}/{LAUNCHD_TRAY_LABEL}"),
            Action("remove_file", str(d / f"{LAUNCHD_LABEL}.plist")),
            Action("remove_file", str(d / f"{LAUNCHD_TRAY_LABEL}.plist")),
        ]

    def status(self) -> AutostartStatus:
        d = self.dir()
        return AutostartStatus(
            self.mechanism,
            (d / f"{LAUNCHD_LABEL}.plist").exists(),
            (d / f"{LAUNCHD_TRAY_LABEL}.plist").exists(),
            {"dir": str(d)},
        )

    def execute(self, actions: list[Action]) -> None:
        for action in actions:
            if action.kind == "run" and "bootout" in action.target:
                self.runner(shlex.split(action.target))  # not loaded -> harmless failure
                continue
            super().execute([action])


def default_backend() -> Backend:
    if sys.platform == "win32":
        return WindowsBackend()
    if sys.platform == "darwin":
        return LaunchdBackend()
    if shutil.which("systemctl") and Path("/run/systemd/system").exists():
        return SystemdBackend()
    return XdgAutostartBackend()


def install(
    home: str | None, *, tray: bool = False, dry_run: bool = False, backend: Backend | None = None
) -> list[Action]:
    backend = backend or default_backend()
    actions = backend.plan_install(home, tray)
    if not dry_run:
        backend.execute(actions)
    return actions


def uninstall(*, dry_run: bool = False, backend: Backend | None = None) -> list[Action]:
    backend = backend or default_backend()
    actions = backend.plan_uninstall()
    if not dry_run:
        backend.execute(actions)
    return actions


def status(backend: Backend | None = None) -> AutostartStatus:
    try:
        return (backend or default_backend()).status()
    except Exception as exc:  # never break status/doctor over autostart introspection
        return AutostartStatus("unknown", False, details={"error": str(exc)})
