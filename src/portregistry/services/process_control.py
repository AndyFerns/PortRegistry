"""Opt-in, audited process control ("Stop process").

Safety model (see README "Stopping processes"):

* Off unless ``[control] enabled = true``; forced off when the daemon listens on a
  non-loopback address.
* Only processes of the daemon's own user account. Other users' processes need
  ``allow_other_users = true`` *and* an elevated daemon. root/SYSTEM-owned,
  service and core OS processes, PortRegistry itself, its parents and the
  requesting client's parents are never stopped.
* Two steps: :func:`request_stop` re-checks the live process and returns a
  single-use code valid for 30 seconds, bound to that exact process (PID +
  creation time), the stop mode and the exact set of tree members.
  :func:`confirm_stop` consumes the code, requires the PID to be typed back,
  re-checks everything and only then acts.
* Graceful first where the OS has a polite stop (SIGTERM; WM_CLOSE for Windows
  programs with a window). Otherwise the action is labelled "immediate stop".
  A process that ignores a graceful stop is never force-stopped automatically.
* Docker containers and OS services are never stopped; the exact command to do
  it yourself is shown instead.
* Every attempt, allowed or refused, is recorded in history.
"""

from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from django.db import connection

from portregistry.config import Config, is_loopback_host
from portregistry.core.application import get_application, has_application
from portregistry.core.identity import process_key
from portregistry.django_app.models import Machine, ProcessInstance, Service, Socket
from portregistry.exceptions import NotFoundError, PortRegistryError, ValidationError
from portregistry.services import queries
from portregistry.services.conflicts import (
    DOCKER_PROXY_NAMES,
    directory_matches,
    executable_matches,
)
from portregistry.services.db import write_transaction
from portregistry.services.history import EventSpec, record_events
from portregistry.services.process_os import (
    AccessDenied,
    IdentityChanged,
    LiveProcess,
    NothingToClose,
    OpenedProcess,
    ProcessGone,
    ProcessOs,
    current_platform,
    default_os,
)

logger = logging.getLogger(__name__)

CODE_TTL_SECONDS = 30
MODES = ("process", "tree")
ACTORS = ("gui", "cli", "tui", "api")
#: Seconds to wait for an immediate/forced stop to take effect.
HARD_STOP_WAIT = 5.0
#: How long the confirm request waits for the operation before answering "running".
CONFIRM_WAIT = 1.5
MAX_ANCESTORS = 64
#: Tests set this to False to run stops inline (no worker thread).
RUN_IN_BACKGROUND = True

PROTECTED_PIDS = frozenset({0, 1, 4})
#: Base names (lower case, no .exe) of processes that are never stopped.
CRITICAL_NAMES = frozenset(
    {
        "system",
        "system idle process",
        "registry",
        "memory compression",
        "secure system",
        "csrss",
        "wininit",
        "winlogon",
        "lsass",
        "lsaiso",
        "smss",
        "services",
        "svchost",
        "dwm",
        "explorer",
        "systemd",
        "init",
        "kthreadd",
        "launchd",
        "kernel_task",
        "windowserver",
        "loginwindow",
    }
)
_WINDOWS_SYSTEM_DOMAINS = frozenset(
    {"nt authority", "nt service", "window manager", "font driver host"}
)
_WINDOWS_SYSTEM_USERS = frozenset({"system", "local service", "network service"})
_CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

METHOD_LABELS = {
    (
        "windows",
        "graceful",
    ): "Polite close (WM_CLOSE to its window). The program may ask to save first.",
    ("windows", "immediate"): (
        "Immediate stop (TerminateProcess). This program has no window to close politely, "
        "so Windows ends it at once without any cleanup."
    ),
    ("windows", "forced"): "Forced stop (TerminateProcess). Ends it at once without any cleanup.",
    ("posix", "graceful"): "Graceful stop (SIGTERM). The program can clean up and exit.",
    ("posix", "forced"): "Forced stop (SIGKILL). Ends it at once without any cleanup.",
}


# ---------------------------------------------------------------------- errors


class ControlError(PortRegistryError):
    code = "control_error"
    http_status = 409


class ControlDisabledError(ControlError):
    code = "control_disabled"
    http_status = 403


class StopRefusedError(ControlError):
    code = "stop_refused"
    http_status = 409


class StopCodeError(ControlError):
    code = "stop_code_invalid"
    http_status = 409


# ----------------------------------------------------------------------- state


def _app_config() -> Config | None:
    return get_application().config if has_application() else None


def _elevated(os_: ProcessOs) -> bool | None:
    if has_application():
        info = get_application().platform_info or {}
        if "elevated" in info:
            value = info.get("elevated")
            return None if value is None else bool(value)
    return os_.is_elevated()


def control_state(
    config: Config | None = None, *, elevated: bool | None = None, os_: ProcessOs | None = None
) -> dict[str, Any]:
    """Effective process-control settings, with a reason whenever something is off."""
    config = config or _app_config()
    if config is None:
        return {"enabled": False, "configured": False, "reason": "Daemon not initialised."}
    if elevated is None:
        elevated = _elevated(os_ or default_os())
    ctl = config.control
    loopback = is_loopback_host(config.daemon.host)
    enabled = ctl.enabled and loopback
    if not ctl.enabled:
        reason = (
            "Process control is off. To turn it on, set enabled = true in the [control] "
            f"section of {config.paths.config_file} and restart the daemon."
        )
    elif not loopback:
        reason = (
            "Process control is forced off because the daemon listens on a non-loopback "
            f"address ({config.daemon.host})."
        )
    else:
        reason = ""
    other_users = enabled and ctl.allow_other_users and elevated is True
    other_note = ""
    if ctl.allow_other_users and not other_users:
        other_note = "allow_other_users is set but has no effect: " + (
            "process control is off." if not enabled else "the daemon is not elevated."
        )
    elif other_users:
        other_note = (
            "The daemon is elevated and allow_other_users is on: other users' processes "
            "can be stopped. Anyone with the API token has that power."
        )
    return {
        "enabled": enabled,
        "configured": ctl.enabled,
        "reason": reason,
        "allow_other_users": other_users,
        "allow_other_users_configured": ctl.allow_other_users,
        "other_users_note": other_note,
        "elevated": elevated,
        "grace_seconds": ctl.grace_seconds,
        "code_ttl_seconds": CODE_TTL_SECONDS,
        "config_file": str(config.paths.config_file),
    }


# ------------------------------------------------------------------ assessment


@dataclass
class Member:
    pid: int
    create_time: float | None
    name: str
    username: str | None
    exe: str = ""
    cmdline: list[str] = field(default_factory=list)
    cwd: str = ""
    depth: int = 0
    method: str = ""
    refusals: list[str] = field(default_factory=list)
    critical: bool = False
    ports: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    process_id: int | None = None

    @property
    def key(self) -> str:
        return process_key(self.pid, self.create_time) if self.create_time is not None else ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "create_time": self.create_time,
            "key": self.key,
            "name": self.name,
            "username": self.username,
            "exe": self.exe,
            "cmdline": self.cmdline,
            "cwd": self.cwd,
            "depth": self.depth,
            "method": self.method,
            "refusals": self.refusals,
            "critical": self.critical,
            "ports": self.ports,
            "services": self.services,
            "process_id": self.process_id,
        }


@dataclass
class Assessment:
    process_id: int
    mode: str
    force: bool
    platform: str
    control: dict[str, Any]
    identity: dict[str, Any]
    live: bool = False
    allowed: bool = False
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    parent_chain: list[dict[str, Any]] = field(default_factory=list)
    members: list[Member] = field(default_factory=list)
    method: str = ""
    docker: list[dict[str, str]] = field(default_factory=list)
    commands: list[dict[str, str]] = field(default_factory=list)
    command_note: str = ""

    @property
    def target(self) -> Member | None:
        return next((m for m in self.members if m.depth == 0), None)

    @property
    def member_keys(self) -> tuple[str, ...]:
        return tuple(sorted(m.key for m in self.members))

    @property
    def method_label(self) -> str:
        if not self.method:
            return ""
        family = "windows" if self.platform == "windows" else "posix"
        return METHOD_LABELS.get((family, self.method), self.method)

    def as_dict(self) -> dict[str, Any]:
        target = self.target
        ports = sorted({p for m in self.members for p in m.ports})
        services = sorted({s for m in self.members for s in m.services})
        methods = sorted({m.method for m in self.members if m.method})
        return {
            "process_id": self.process_id,
            "mode": self.mode,
            "force": self.force,
            "platform": self.platform,
            "control": self.control,
            "control_enabled": bool(self.control.get("enabled")),
            "identity": self.identity,
            "live": self.live,
            "allowed": self.allowed,
            "can_request": self.allowed and bool(self.control.get("enabled")),
            "reasons": self.reasons,
            "warnings": self.warnings,
            "target": target.as_dict() if target else None,
            "parent_chain": self.parent_chain,
            "members": [m.as_dict() for m in self.members],
            "stop_order": [m.pid for m in self.members],
            "method": self.method,
            "method_label": self.method_label,
            "graceful": self.method == "graceful",
            "mixed_methods": len(methods) > 1,
            "member_methods": methods,
            "impact": {"processes": len(self.members), "ports": ports, "services": services},
            "docker": self.docker,
            "commands": self.commands,
            "command_note": self.command_note,
        }


def _base(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
    return base[:-4] if base.endswith(".exe") else base


def _same_user(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and str(a).strip().lower() == str(b).strip().lower()


def _is_system_account(live: LiveProcess, platform: str, daemon_uid: int | None) -> bool:
    user = (live.username or "").strip().lower()
    if platform == "windows":
        domain, _, name = user.rpartition("\\")
        return domain in _WINDOWS_SYSTEM_DOMAINS or name in _WINDOWS_SYSTEM_USERS
    if live.uid == 0 or user == "root" or user.startswith("_"):
        return True
    if live.uid is not None and live.uid != daemon_uid:
        limit = 500 if platform == "macos" else 1000
        return 0 < live.uid < limit
    return False


def _ancestors(os_: ProcessOs, live: LiveProcess | None, limit: int = 32) -> list[LiveProcess]:
    """Parent chain, stopping where a "parent" started after its child (reused PID)."""
    chain: list[LiveProcess] = []
    seen: set[int] = set()
    current = live
    while current is not None and current.ppid and len(chain) < limit:
        if current.ppid in seen or current.ppid == current.pid:
            break
        parent = os_.lookup(current.ppid)
        if parent is None:
            break
        if (
            parent.create_time is not None
            and current.create_time is not None
            and parent.create_time > current.create_time + 0.5
        ):
            break  # the original parent exited and its PID was reused
        chain.append(parent)
        seen.add(parent.pid)
        current = parent
    return chain


@dataclass
class _Context:
    os: ProcessOs
    platform: str
    control: dict[str, Any]
    daemon_user: str | None
    daemon_uid: int | None
    protected: dict[int, str]
    services: frozenset[int]


def _context(os_: ProcessOs, client_ancestors: tuple[int, ...]) -> _Context:
    control = control_state(os_=os_)
    daemon_pid = os_.daemon_pid()
    daemon = os_.lookup(daemon_pid)
    protected: dict[int, str] = {}
    protected[daemon_pid] = (
        "This is the PortRegistry daemon itself. Use `portregistry daemon stop`."
    )
    for parent in _ancestors(os_, daemon):
        protected.setdefault(parent.pid, "This is a parent process of the PortRegistry daemon.")
    for pid in client_ancestors:
        protected.setdefault(
            pid, "This is the program you are using to make this request (or one of its parents)."
        )
    return _Context(
        os=os_,
        platform=os_.platform,
        control=control,
        daemon_user=daemon.username if daemon else None,
        daemon_uid=daemon.uid if daemon else None,
        protected=protected,
        services=os_.service_pids() if os_.platform == "windows" else frozenset(),
    )


def _check(live: LiveProcess, ctx: _Context) -> tuple[list[str], list[str], bool]:
    """(refusals, warnings, critical) for one live process."""
    refusals: list[str] = []
    warnings: list[str] = []
    critical = False
    base = _base(live.name or live.exe)
    label = f"{live.name or '?'} (PID {live.pid})"
    if live.pid in PROTECTED_PIDS:
        refusals.append(f"{label} is a core operating-system process.")
        critical = True
    if live.pid in ctx.protected:
        refusals.append(ctx.protected[live.pid])
        critical = critical or live.pid == ctx.os.daemon_pid()
    if ctx.platform == "linux" and (live.pid == 2 or live.ppid == 2):
        refusals.append(f"{label} is a kernel thread.")
        critical = True
    if base in CRITICAL_NAMES:
        refusals.append(f"{label} is a critical system process.")
        critical = True
    if live.pid in ctx.services:
        refusals.append(
            f"{label} runs a Windows service. PortRegistry does not stop services; use the "
            "Services app (services.msc) if you really need to."
        )
        critical = True
    if base in DOCKER_PROXY_NAMES:
        refusals.append(
            f"{label} is Docker's port proxy. Stop the container instead (see the Docker command)."
        )
    if live.username is None:
        refusals.append(
            f"The owner of {label} could not be read (usually another user's or a system process)."
        )
    elif _is_system_account(live, ctx.platform, ctx.daemon_uid):
        refusals.append(f"{label} runs as the system account {live.username}.")
        critical = True
    elif not _same_user(live.username, ctx.daemon_user):
        if ctx.control.get("allow_other_users"):
            warnings.append(
                f"{label} belongs to another user ({live.username}); allowed because the "
                "daemon is elevated and allow_other_users is on."
            )
        else:
            refusals.append(
                f"{label} belongs to another user ({live.username}). Only your own "
                f"processes ({ctx.daemon_user or 'unknown'}) can be stopped."
            )
    return refusals, warnings, critical


def _method(live: LiveProcess, force: bool, ctx: _Context) -> str:
    if force:
        return "forced"
    if ctx.platform == "windows":
        return "graceful" if ctx.os.has_visible_window(live.pid) else "immediate"
    return "graceful"


def _db_record(machine: Machine, pid: int, create_time: float | None) -> ProcessInstance | None:
    if create_time is None:
        return None
    return ProcessInstance.objects.filter(
        machine=machine, identity_key=process_key(pid, create_time)
    ).first()


def _impact(machine: Machine, member: Member, services: list[Service]) -> None:
    record = _db_record(machine, member.pid, member.create_time)
    names: set[str] = set()
    if record is not None:
        member.process_id = record.pk
        for sock in Socket.objects.filter(process=record, active=True).order_by("port"):
            member.ports.append(str(sock))
            for res in queries.reservations_covering(sock):
                if res.service is not None:
                    names.add(f"{res.service.name} (reserves {res})")
                else:
                    names.add(f"reservation #{res.pk} ({res})")
    for svc in services:
        exe_ok = executable_matches(svc.expected_executable, member.exe, member.name)
        dir_ok = directory_matches(svc.expected_working_directory, member.cwd)
        if exe_ok and dir_ok:
            names.add(f"{svc.name} (expected program and folder match)")
    member.services = sorted(names)


def _docker_hints(record: ProcessInstance) -> list[dict[str, str]]:
    index = queries.docker_index(record.machine)
    hints: list[dict[str, str]] = []
    seen: set[str] = set()
    for sock in Socket.objects.filter(process=record, active=True):
        for mapping in queries.docker_matches_for(sock, index):
            container = mapping.container
            name = container.name if _CONTAINER_NAME.match(container.name) else container.short_id
            if name in seen:
                continue
            seen.add(name)
            hints.append(
                {"container": container.name, "port": str(sock), "command": f"docker stop {name}"}
            )
    return hints


def _commands(platform: str, mode: str, members: list[Member]) -> list[dict[str, str]]:
    target = next(m for m in members if m.depth == 0)
    pid = target.pid
    if platform == "windows":
        if mode == "tree":
            return [
                {
                    "label": "Ask the whole tree to close (programs without a window ignore it)",
                    "command": f"taskkill /PID {pid} /T",
                },
                {"label": "Force-stop the whole tree", "command": f"taskkill /PID {pid} /T /F"},
            ]
        return [
            {
                "label": "Ask it to close (programs without a window ignore it)",
                "command": f"taskkill /PID {pid}",
            },
            {"label": "Force-stop", "command": f"taskkill /PID {pid} /F"},
        ]
    pids = " ".join(str(m.pid) for m in members)
    return [
        {"label": "Graceful stop (SIGTERM)", "command": f"kill -TERM {pids}"},
        {"label": "Force-stop (SIGKILL)", "command": f"kill -KILL {pids}"},
    ]


def _identity(process: ProcessInstance) -> dict[str, Any]:
    return {
        "process_id": process.pk,
        "identity_key": process.identity_key,
        "pid": process.pid,
        "create_time": process.create_time,
        "name": process.name,
        "exe": process.exe,
        "cmdline": process.cmdline or [],
        "username": process.username,
        "cwd": process.cwd,
        "project": process.project_name,
    }


def _get_process(process_id: int) -> ProcessInstance:
    try:
        return ProcessInstance.objects.select_related("machine").get(pk=process_id)
    except ProcessInstance.DoesNotExist as exc:
        raise NotFoundError(f"Process {process_id} not found.") from exc


def assess(
    process: ProcessInstance,
    *,
    mode: str = "process",
    force: bool = False,
    client_ancestors: tuple[int, ...] = (),
    os_: ProcessOs | None = None,
) -> Assessment:
    """Re-read the live process and decide whether (and how) it may be stopped."""
    if mode not in MODES:
        raise ValidationError("Invalid stop mode.", {"mode": ["Use 'process' or 'tree'."]})
    os_ = os_ or default_os()
    ctx = _context(os_, client_ancestors)
    result = Assessment(
        process_id=process.pk,
        mode=mode,
        force=force,
        platform=ctx.platform,
        control=ctx.control,
        identity=_identity(process),
    )
    if not ctx.control.get("enabled"):
        result.warnings.append(str(ctx.control.get("reason") or "Process control is off."))
    if process.create_time is None or not process.identity_complete:
        result.reasons.append(
            "This process record has no creation time, so its identity cannot be verified. "
            "PortRegistry only stops processes it can identify exactly."
        )
        return result
    live = os_.lookup(process.pid)
    if live is None or not live.matches(process.create_time):
        result.reasons.append(
            f"The process has exited or PID {process.pid} now belongs to a different process. "
            "Nothing will be stopped; refresh and review again."
        )
        return result
    result.live = True

    result.parent_chain = [
        {
            "pid": p.pid,
            "name": p.name,
            "username": p.username,
            "protected": p.pid in ctx.protected or p.pid in PROTECTED_PIDS,
        }
        for p in _ancestors(os_, live)
    ]

    lives: list[tuple[LiveProcess, int]] = [(live, 0)]
    if mode == "tree":
        depth_of: dict[int, int] = {live.pid: 0}
        pending = [os_.lookup(pid) for pid in os_.descendants(live.pid)]
        children = [c for c in pending if c is not None]
        # Resolve depth through ppid links (descendants arrive in any order).
        for _ in range(len(children) + 1):
            for child in children:
                if child.pid not in depth_of and child.ppid in depth_of:
                    depth_of[child.pid] = depth_of[child.ppid] + 1
        for child in children:
            lives.append((child, depth_of.get(child.pid, 1)))

    services = list(Service.objects.filter(machine=process.machine).exclude(expected_executable=""))
    critical_target = False
    for proc, depth in lives:
        refusals, warnings, critical = _check(proc, ctx)
        if proc.create_time is None:
            refusals.append(f"The creation time of PID {proc.pid} could not be read.")
        member = Member(
            pid=proc.pid,
            create_time=proc.create_time,
            name=proc.name,
            username=proc.username,
            exe=proc.exe,
            cmdline=list(proc.cmdline),
            cwd=proc.cwd,
            depth=depth,
            method=_method(proc, force, ctx),
            refusals=refusals,
            critical=critical,
        )
        _impact(process.machine, member, services)
        result.members.append(member)
        result.warnings.extend(warnings)
        if depth == 0:
            critical_target = critical
            result.reasons.extend(refusals)
        else:
            result.reasons.extend(f"In the tree: {r}" for r in refusals)

    # Children first (deepest first), the target last.
    result.members.sort(key=lambda m: (-m.depth, m.pid))
    target = result.target
    assert target is not None
    result.method = target.method
    if mode == "tree" and len(result.members) == 1:
        result.warnings.append("This process has no child processes; only it will be stopped.")
    if mode == "tree" and len({m.method for m in result.members}) > 1:
        result.warnings.append("Tree members are stopped with different methods (see each member).")
    if not process.active:
        result.warnings.append("This process no longer owns any observed endpoints.")

    docker_target = _base(target.name or target.exe) in DOCKER_PROXY_NAMES
    if docker_target:
        result.docker = _docker_hints(process)
        if not result.docker:
            result.docker = [
                {
                    "container": "",
                    "port": ", ".join(target.ports),
                    "command": "docker ps --format '{{.Names}} {{.Ports}}'",
                }
            ]
    else:
        for hint in _docker_hints(process):
            result.warnings.append(
                f"Container {hint['container']} also publishes {hint['port']}; to stop it "
                f"use `{hint['command']}`."
            )

    if docker_target:
        result.command_note = "Stop the container with Docker instead of the proxy process."
    elif critical_target:
        result.command_note = (
            "No stop commands are shown for system, service or PortRegistry processes."
        )
    else:
        result.commands = _commands(ctx.platform, mode, result.members)
        result.command_note = (
            "Copy-and-run alternative. These commands act on the PID as it is right now; PIDs "
            "are reused by the OS, so run them only straight after checking."
        )
    result.allowed = not result.reasons
    return result


# ------------------------------------------------------------------- auditing


def _actor(actor: str) -> str:
    return actor if actor in ACTORS else "api"


def _audit(
    machine: Machine | None,
    type_: str,
    severity: str,
    summary: str,
    entity_id: int | str,
    details: dict[str, Any],
) -> None:
    with write_transaction():
        record_events(
            machine,
            [
                EventSpec(
                    type_,
                    summary,
                    severity=severity,
                    entity_type="process",
                    entity_id=entity_id,
                    details=details,
                )
            ],
        )


def _who(process: ProcessInstance | dict[str, Any]) -> str:
    if isinstance(process, dict):
        return f"{process.get('name') or '?'} (PID {process.get('pid')})"
    return f"{process.name or '?'} (PID {process.pid})"


def _refuse(
    machine: Machine | None,
    *,
    stage: str,
    actor: str,
    reasons: list[str],
    identity: dict[str, Any] | None,
    process_id: int | str = "",
    mode: str = "",
    force: bool = False,
    error: type[ControlError] = StopRefusedError,
    message: str = "",
    assessment: dict[str, Any] | None = None,
) -> ControlError:
    who = _who(identity) if identity else "unknown process"
    summary = f"Stop of {who} refused ({actor.upper()}): {reasons[0] if reasons else ''}"
    _audit(
        machine,
        "process.stop_refused",
        "warning",
        summary,
        process_id,
        {
            "actor": actor,
            "stage": stage,
            "mode": mode,
            "force": force,
            "reasons": reasons,
            "identity": identity or {},
        },
    )
    details: dict[str, Any] = {"reasons": reasons}
    if assessment is not None:
        details["assessment"] = assessment
    return error(message or (reasons[0] if reasons else "Stop refused."), details=details)


# ------------------------------------------------------------- request/confirm


@dataclass(frozen=True)
class PendingStop:
    process_id: int
    identity_key: str
    pid: int
    create_time: float
    mode: str
    force: bool
    member_keys: tuple[str, ...]
    actor: str
    client_ancestors: tuple[int, ...]


def preview(
    process_id: int,
    *,
    mode: str = "process",
    force: bool = False,
    client_ancestors: tuple[int, ...] = (),
    os_: ProcessOs | None = None,
) -> dict[str, Any]:
    """Assessment and copy-and-run commands; never issues a code (works when disabled)."""
    return assess(
        _get_process(process_id),
        mode=mode,
        force=force,
        client_ancestors=client_ancestors,
        os_=os_,
    ).as_dict()


def request_stop(
    process_id: int,
    *,
    mode: str = "process",
    force: bool = False,
    actor: str = "api",
    client_ancestors: tuple[int, ...] = (),
    os_: ProcessOs | None = None,
) -> dict[str, Any]:
    """Step 1: re-check the process and issue a single-use confirmation code."""
    actor = _actor(actor)
    process = _get_process(process_id)
    machine = process.machine
    assessment = assess(process, mode=mode, force=force, client_ancestors=client_ancestors, os_=os_)
    data = assessment.as_dict()
    common: dict[str, Any] = {
        "stage": "request",
        "actor": actor,
        "identity": assessment.identity,
        "process_id": process.pk,
        "mode": mode,
        "force": force,
        "assessment": data,
    }
    if not assessment.control.get("enabled"):
        raise _refuse(
            machine,
            reasons=[str(assessment.control.get("reason") or "Process control is off.")],
            error=ControlDisabledError,
            **common,
        )
    if not assessment.allowed:
        raise _refuse(machine, reasons=assessment.reasons, **common)
    target = assessment.target
    assert target is not None and target.create_time is not None
    pending = PendingStop(
        process_id=process.pk,
        identity_key=process.identity_key,
        pid=target.pid,
        create_time=target.create_time,
        mode=mode,
        force=force,
        member_keys=assessment.member_keys,
        actor=actor,
        client_ancestors=client_ancestors,
    )
    code = get_application().control_codes.issue(pending)
    if code is None:
        raise _refuse(
            machine,
            reasons=["Too many stop requests are waiting for confirmation; try again shortly."],
            **common,
        )
    _audit(
        machine,
        "process.stop_requested",
        "info",
        f"Stop of {_who(process)} reviewed from {actor.upper()} "
        f"({assessment.mode}, {assessment.method}); waiting for confirmation",
        process.pk,
        {
            "actor": actor,
            "mode": mode,
            "force": force,
            "method": assessment.method,
            "identity": assessment.identity,
            "members": [m.as_dict() for m in assessment.members],
        },
    )
    ttl = int(get_application().control_codes.ttl)
    return {"code": code, "expires_in": ttl, "assessment": data}


def confirm_stop(
    code: str,
    *,
    pid: Any,
    actor: str = "api",
    client_ancestors: tuple[int, ...] = (),
    os_: ProcessOs | None = None,
) -> dict[str, Any]:
    """Step 2: consume the code, re-check everything, then stop."""
    actor = _actor(actor)
    app = get_application()
    status, pending = app.control_codes.consume(str(code or ""))
    if status != "ok" or not isinstance(pending, PendingStop):
        reason = (
            "The confirmation code has expired (codes are valid for "
            f"{CODE_TTL_SECONDS} seconds). Review the stop again."
            if status == "expired"
            else "Unknown or already-used confirmation code. Review the stop again."
        )
        process_id = pending.process_id if isinstance(pending, PendingStop) else ""
        identity = None
        machine = None
        if isinstance(pending, PendingStop):
            record = (
                ProcessInstance.objects.select_related("machine")
                .filter(pk=pending.process_id)
                .first()
            )
            if record is not None:
                identity, machine = _identity(record), record.machine
        if machine is None:
            machine = Machine.objects.filter(is_local=True).first()
        raise _refuse(
            machine,
            stage="confirm",
            actor=actor,
            reasons=[reason],
            identity=identity,
            process_id=process_id,
            error=StopCodeError,
        )
    process = _get_process(pending.process_id)
    machine = process.machine
    common: dict[str, Any] = {
        "stage": "confirm",
        "actor": actor,
        "identity": _identity(process),
        "process_id": process.pk,
        "mode": pending.mode,
        "force": pending.force,
    }
    if actor != pending.actor:
        raise _refuse(
            machine,
            reasons=[
                f"This code was issued to the {pending.actor.upper()}; confirm it from there."
            ],
            **common,
        )
    try:
        typed = int(str(pid).strip())
    except (TypeError, ValueError):
        typed = -1
    if typed != pending.pid:
        raise _refuse(
            machine,
            reasons=[
                f"The PID you typed does not match the process to stop (PID {pending.pid}). "
                "Nothing was stopped; review again."
            ],
            **common,
        )
    ancestors = tuple(sorted(set(pending.client_ancestors) | set(client_ancestors)))
    assessment = assess(
        process, mode=pending.mode, force=pending.force, client_ancestors=ancestors, os_=os_
    )
    common["assessment"] = assessment.as_dict()
    if not assessment.control.get("enabled"):
        raise _refuse(
            machine,
            reasons=[str(assessment.control.get("reason") or "Process control is off.")],
            error=ControlDisabledError,
            **common,
        )
    if not assessment.allowed:
        raise _refuse(machine, reasons=assessment.reasons, **common)
    if (
        process.identity_key != pending.identity_key
        or assessment.member_keys != pending.member_keys
    ):
        raise _refuse(
            machine,
            reasons=[
                "The process tree changed since you reviewed it (processes started or "
                "exited). Nothing was stopped; review again."
            ],
            **common,
        )
    operation = StopOperation(
        id=uuid.uuid4().hex[:16],
        process_id=process.pk,
        actor=actor,
        mode=pending.mode,
        force=pending.force,
        platform=assessment.platform,
        method=assessment.method,
        method_label=assessment.method_label,
        identity=_identity(process),
        members=[
            MemberResult(
                pid=m.pid,
                create_time=m.create_time or 0.0,
                name=m.name,
                method=m.method,
                ports=list(m.ports),
            )
            for m in assessment.members
        ],
        grace_seconds=float(assessment.control.get("grace_seconds") or 10),
    )
    operations(app).add(operation)
    _start(operation, machine, os_ or default_os())
    operation.done.wait(CONFIRM_WAIT if RUN_IN_BACKGROUND else 0)
    return operation.as_dict()


# -------------------------------------------------------------------- execution


@dataclass
class MemberResult:
    pid: int
    create_time: float
    name: str
    method: str
    ports: list[str] = field(default_factory=list)
    result: str = "pending"  # stopped | already_exited | still_running | failed | skipped
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "name": self.name,
            "method": self.method,
            "ports": self.ports,
            "result": self.result,
            "detail": self.detail,
        }


@dataclass
class StopOperation:
    id: str
    process_id: int
    actor: str
    mode: str
    force: bool
    platform: str
    method: str
    method_label: str
    identity: dict[str, Any]
    members: list[MemberResult]
    grace_seconds: float = 10.0
    state: str = "running"  # running | done
    outcome: str = ""  # stopped | timeout | partial | failed
    message: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    done: threading.Event = field(default_factory=threading.Event)

    def as_dict(self) -> dict[str, Any]:
        duration = None
        if self.finished_at is not None:
            duration = int((self.finished_at - self.started_at).total_seconds() * 1000)
        return {
            "id": self.id,
            "process_id": self.process_id,
            "actor": self.actor,
            "mode": self.mode,
            "force": self.force,
            "method": self.method,
            "method_label": self.method_label,
            "identity": self.identity,
            "state": self.state,
            "outcome": self.outcome,
            "message": self.message,
            "members": [m.as_dict() for m in self.members],
            "grace_seconds": self.grace_seconds,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_ms": duration,
        }


class OperationLog:
    """The most recent stop operations (daemon memory; history holds the audit trail)."""

    def __init__(self, keep: int = 50) -> None:
        self._keep = keep
        self._lock = threading.Lock()
        self._ops: OrderedDict[str, StopOperation] = OrderedDict()

    def add(self, op: StopOperation) -> None:
        with self._lock:
            self._ops[op.id] = op
            while len(self._ops) > self._keep:
                self._ops.popitem(last=False)

    def get(self, op_id: str) -> StopOperation | None:
        with self._lock:
            return self._ops.get(op_id)


_ops_lock = threading.Lock()


def operations(app: Any = None) -> OperationLog:
    app = app or get_application()
    with _ops_lock:
        if app.stop_operations is None:
            app.stop_operations = OperationLog()
        log: OperationLog = app.stop_operations
        return log


def get_operation(op_id: str) -> dict[str, Any]:
    op = operations().get(op_id)
    if op is None:
        raise NotFoundError(
            "Stop operation not found (operations are kept in memory until the daemon "
            "restarts; see History for the audit trail)."
        )
    return op.as_dict()


def _start(op: StopOperation, machine: Machine, os_: ProcessOs) -> None:
    if not RUN_IN_BACKGROUND:
        _run(op, machine, os_)
        return

    def worker() -> None:
        try:
            _run(op, machine, os_)
        finally:
            connection.close()

    threading.Thread(target=worker, name=f"stop-{op.id}", daemon=True).start()


def _execute(op: StopOperation, os_: ProcessOs) -> None:
    opened: list[tuple[MemberResult, OpenedProcess]] = []
    try:
        for member in op.members:  # children first, target last
            try:
                handle = os_.open(member.pid, member.create_time)
            except ProcessGone:
                member.result, member.detail = "already_exited", "Exited before it was stopped."
                continue
            except IdentityChanged:
                member.result = "skipped"
                member.detail = "The PID now belongs to a different process; not touched."
                continue
            except AccessDenied:
                member.result, member.detail = "failed", "The OS denied access to the process."
                continue
            try:
                handle.send(member.method)
            except NothingToClose:
                member.result = "failed"
                member.detail = (
                    "Its window closed before the request was sent; nothing was sent. Review "
                    "again (it will be offered as an immediate stop)."
                )
                handle.close()
                continue
            except ProcessGone:
                member.result, member.detail = "already_exited", "Exited before it was stopped."
                handle.close()
                continue
            except (AccessDenied, OSError) as exc:
                member.result, member.detail = "failed", f"The OS refused the stop: {exc}"
                handle.close()
                continue
            opened.append((member, handle))
        start = time.monotonic()
        for member, handle in opened:
            budget = op.grace_seconds if member.method == "graceful" else HARD_STOP_WAIT
            remaining = max(0.0, start + budget - time.monotonic())
            if handle.wait(remaining):
                member.result = "stopped"
                member.detail = {
                    "graceful": "Exited after the polite stop request.",
                    "immediate": "Ended immediately (no polite stop available).",
                    "forced": "Force-stopped.",
                }.get(member.method, "Stopped.")
            else:
                member.result = "still_running"
                member.detail = f"Still running after {budget:g} s. It was not force-stopped. " + (
                    "It may be asking a question (for example about unsaved work); "
                    "check its window."
                    if op.platform == "windows" and member.method == "graceful"
                    else "Review again and choose the forced stop if you are sure."
                )
    finally:
        for _member, handle in opened:
            try:
                handle.close()
            except OSError:
                pass


def _outcome(op: StopOperation) -> tuple[str, str, str, str]:
    """(outcome, event type, severity, message)."""
    results = [m.result for m in op.members]
    done = all(r in ("stopped", "already_exited") for r in results)
    if done:
        return "stopped", "process.stopped", "warning", "Stopped."
    if any(r in ("failed", "skipped") for r in results):
        if any(r == "stopped" for r in results):
            return "partial", "process.stop_failed", "error", "Only part of the tree was stopped."
        return "failed", "process.stop_failed", "error", "The stop failed."
    return (
        "timeout",
        "process.stop_timeout",
        "warning",
        "The process did not exit in time and was NOT force-stopped.",
    )


def _run(op: StopOperation, machine: Machine, os_: ProcessOs) -> None:
    try:
        _execute(op, os_)
        op.outcome, event_type, severity, op.message = _outcome(op)
    except Exception as exc:  # never leave an operation hanging
        logger.exception("Process stop operation %s failed", op.id)
        op.outcome, event_type, severity = "failed", "process.stop_failed", "error"
        op.message = f"Internal error: {exc}"
    op.finished_at = datetime.now(UTC)
    op.state = "done"
    who = _who(op.identity)
    verb = {
        "stopped": "Stopped",
        "timeout": "Stop timed out for",
        "partial": "Partly stopped",
        "failed": "Failed to stop",
    }[op.outcome]
    tree = " and its tree" if op.mode == "tree" else ""
    summary = f"{verb} {who}{tree} ({op.actor.upper()}, {op.method})"
    try:
        _audit(
            machine,
            event_type,
            severity,
            summary,
            op.process_id,
            {
                "actor": op.actor,
                "operation": op.id,
                "mode": op.mode,
                "force": op.force,
                "method": op.method,
                "outcome": op.outcome,
                "identity": op.identity,
                "members": [m.as_dict() for m in op.members],
                "duration_ms": op.as_dict()["duration_ms"],
            },
        )
    except Exception:
        logger.exception("Could not record the audit event for stop operation %s", op.id)
    finally:
        op.done.set()
    if has_application():
        scheduler = get_application().scheduler
        if scheduler is not None:
            try:
                scheduler.request_native_scan(None, None, "process-stop")
            except Exception:
                logger.debug("Could not request a scan after a stop", exc_info=True)


def parse_ancestors(raw: str | None) -> tuple[int, ...]:
    """Parse the ``X-PortRegistry-Client-Ancestors`` header (only ever used to *block*)."""
    if not raw:
        return ()
    pids: list[int] = []
    for part in raw.split(",")[:MAX_ANCESTORS]:
        part = part.strip()
        if part.isdigit():
            pids.append(int(part))
    return tuple(pids)


__all__ = [
    "ACTORS",
    "Assessment",
    "ControlDisabledError",
    "ControlError",
    "StopCodeError",
    "StopRefusedError",
    "assess",
    "confirm_stop",
    "control_state",
    "current_platform",
    "get_operation",
    "parse_ancestors",
    "preview",
    "request_stop",
]
