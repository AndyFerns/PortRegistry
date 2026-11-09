"""Client-side daemon control: start (detached), stop, status.

Used by the CLI. Nothing here imports Django or touches the database.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import psutil

from portregistry.config import Config, load_config, read_token
from portregistry.daemon.lock import read_state, state_process_alive
from portregistry.exceptions import (
    DaemonAlreadyRunningError,
    DaemonNotRunningError,
    PortRegistryError,
)
from portregistry.paths import AppPaths, ensure_dirs, get_paths


def _url_for(host: str, port: int) -> str:
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    if ":" in host:
        host = f"[{host}]"
    return f"http://{host}:{port}"


def is_frozen() -> bool:
    """True when running from a PyInstaller bundle."""
    return bool(getattr(sys, "frozen", False))


def cli_command(*, windowless: bool = False) -> list[str]:
    """Command prefix that invokes the PortRegistry CLI with this installation.

    * PyInstaller bundle: the bundle executable itself.
    * Python install: ``python -m portregistry`` (``pythonw`` on Windows when a
      windowless process is wanted, e.g. for login autostart).
    """
    if is_frozen():
        return [sys.executable]
    exe = sys.executable
    if windowless and sys.platform == "win32":
        candidate = Path(exe).with_name("pythonw.exe")
        if candidate.exists():
            exe = str(candidate)
    return [exe, "-m", "portregistry"]


def check_health(base_url: str, timeout: float = 2.0) -> dict[str, Any] | None:
    try:
        response = httpx.get(f"{base_url}/api/v1/health/", timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, dict) and data.get("service") == "portregistry":
                return data
    except (httpx.HTTPError, ValueError):
        return None
    return None


def daemon_status(paths: AppPaths | None = None, config: Config | None = None) -> dict[str, Any]:
    paths = paths or get_paths()
    config = config or load_config(paths)
    state = read_state(paths.state_file)
    alive = state_process_alive(state)
    if alive and state:
        url = _url_for(str(state.get("host")), int(state.get("port", config.daemon.port)))
    else:
        url = config.base_url
    health = check_health(url)
    return {
        "running": alive,
        "healthy": health is not None and health.get("status") == "ok",
        "health": health,
        "pid": state.get("pid") if alive and state else None,
        "url": url,
        "started_at": state.get("started_at") if alive and state else None,
        "version": state.get("version") if alive and state else None,
        "stale_state_file": bool(state) and not alive,
        "paths": paths.as_dict(),
    }


def _tail(path: Any, lines: int = 20) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return "".join(handle.readlines()[-lines:])
    except OSError:
        return ""


def _spawn(
    cmd: list[str], env: dict[str, str], log_handle: Any, cwd: str
) -> subprocess.Popen[bytes]:
    common: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": log_handle,
        "stderr": subprocess.STDOUT,
        "env": env,
        "cwd": cwd,
        "close_fds": True,
    }
    if sys.platform == "win32":
        # CREATE_NO_WINDOW (not DETACHED_PROCESS) so that the venv launcher's child
        # python process inherits a hidden console instead of opening a new window.
        base = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        try:
            return subprocess.Popen(
                cmd, creationflags=base | subprocess.CREATE_BREAKAWAY_FROM_JOB, **common
            )
        except OSError:
            # The parent's job object forbids breakaway; start inside it.
            return subprocess.Popen(cmd, creationflags=base, **common)
    return subprocess.Popen(cmd, start_new_session=True, **common)


def start_daemon(
    *, port: int | None = None, timeout: float = 45.0, paths: AppPaths | None = None
) -> dict[str, Any]:
    """Start the daemon in the background and wait until it is healthy."""
    paths = paths or get_paths()
    env = os.environ.copy()
    if port is not None:
        env["PORTREGISTRY_PORT"] = str(port)
        os.environ["PORTREGISTRY_PORT"] = str(port)
    config = load_config(paths)
    status = daemon_status(paths, config)
    if status["running"]:
        raise DaemonAlreadyRunningError(
            f"PortRegistry daemon is already running (pid {status['pid']}, {status['url']}).",
            details=status,
        )
    if status["healthy"]:
        raise DaemonAlreadyRunningError(
            f"A PortRegistry daemon is already answering at {status['url']}.", details=status
        )
    ensure_dirs(paths)
    env["PYTHONUNBUFFERED"] = "1"
    cmd = [*cli_command(), "daemon", "run", "--quiet"]
    with open(paths.bootstrap_log_file, "ab") as log_handle:
        log_handle.write(f"\n--- start {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n".encode())
        log_handle.flush()
        proc = _spawn(cmd, env, log_handle, str(paths.data_dir))

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        code = proc.poll()
        if code is not None:
            # The venv launcher may exit only when its child does; either way: failed.
            raise PortRegistryError(
                f"The daemon exited during startup (exit code {code}).\n"
                + (_tail(paths.log_file) or _tail(paths.bootstrap_log_file)),
                details={"exit_code": code},
            )
        status = daemon_status(paths, config)
        if status["running"] and status["healthy"]:
            return status
        time.sleep(0.25)
    raise PortRegistryError(
        f"The daemon did not become healthy within {timeout:.0f}s. Check logs: "
        f"{paths.log_file}\n{_tail(paths.log_file)}"
    )


def stop_daemon(
    *, timeout: float = 25.0, force: bool = False, paths: AppPaths | None = None
) -> dict[str, Any]:
    """Graceful shutdown via the API; optional forced termination as a fallback."""
    paths = paths or get_paths()
    config = load_config(paths)
    status = daemon_status(paths, config)
    if not status["running"]:
        raise DaemonNotRunningError("PortRegistry daemon is not running.", details=status)
    pid = int(status["pid"])
    state = read_state(paths.state_file)
    graceful = False
    token = read_token(paths)
    try:
        response = httpx.post(
            f"{status['url']}/api/v1/daemon/shutdown/",
            headers={"Authorization": f"Bearer {token}"} if token else {},
            timeout=5,
        )
        graceful = response.status_code == 202
    except httpx.HTTPError:
        graceful = False

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not state_process_alive(state):
            return {"stopped": True, "graceful": graceful, "pid": pid, "forced": False}
        time.sleep(0.25)

    if not force:
        raise PortRegistryError(
            f"Daemon (pid {pid}) did not stop within {timeout:.0f}s. "
            "Retry with --force to terminate it."
        )
    # Only terminate the exact process recorded in the state file (pid + create time).
    if state_process_alive(state):
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(10)
        except psutil.TimeoutExpired:
            proc.kill()
        except psutil.NoSuchProcess:
            pass
    return {"stopped": True, "graceful": False, "pid": pid, "forced": True}


def read_log_tail(paths: AppPaths | None = None, lines: int = 50) -> str:
    paths = paths or get_paths()
    return _tail(paths.log_file, lines)
