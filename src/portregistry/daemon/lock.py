"""Single-instance protection for the daemon.

An exclusive OS-level lock (``msvcrt.locking`` on Windows, ``fcntl.flock`` on
POSIX) is held on ``daemon.lock`` for the daemon's lifetime. The OS releases it
automatically if the process dies, so a crash never leaves a stale lock.

``daemon.json`` records pid, process creation time, host and port. It is
informational: it is only trusted when the recorded PID is alive *and* has the
same creation time (guarding against PID reuse); otherwise it is stale.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import IO, Any

import psutil

from portregistry.exceptions import DaemonAlreadyRunningError, LockError
from portregistry.paths import write_private_file


def read_state(state_path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return None
    return data if isinstance(data, dict) else None


def state_process_alive(state: dict[str, Any] | None) -> bool:
    """True only if the PID in the state file is alive and is the same process."""
    if not state:
        return False
    try:
        pid = int(state["pid"])
        recorded = float(state["create_time"])
    except (KeyError, TypeError, ValueError):
        return False
    try:
        proc = psutil.Process(pid)
        return abs(proc.create_time() - recorded) < 0.01
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return False


def _try_lock(handle: IO[bytes]) -> bool:
    handle.seek(0)
    if sys.platform == "win32":
        import msvcrt

        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    import fcntl

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _unlock(handle: IO[bytes]) -> None:
    handle.seek(0)
    if sys.platform == "win32":
        import msvcrt

        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    else:
        import fcntl

        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass


class DaemonLock:
    def __init__(self, lock_path: Path, state_path: Path) -> None:
        self.lock_path = lock_path
        self.state_path = state_path
        self._handle: IO[bytes] | None = None

    @property
    def held(self) -> bool:
        return self._handle is not None

    def acquire(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            handle = open(self.lock_path, "a+b")  # noqa: SIM115 - held for process lifetime
        except OSError as exc:
            raise LockError(f"Cannot open lock file {self.lock_path}: {exc}") from exc
        if handle.tell() == 0 and os.fstat(handle.fileno()).st_size == 0:
            handle.write(b"\0")
            handle.flush()
        if not _try_lock(handle):
            handle.close()
            state = read_state(self.state_path)
            if state_process_alive(state):
                assert state is not None
                raise DaemonAlreadyRunningError(
                    f"PortRegistry daemon is already running (pid {state.get('pid')}, "
                    f"http://{state.get('host')}:{state.get('port')}).",
                    details={"state": state},
                )
            raise DaemonAlreadyRunningError(
                "Another PortRegistry daemon holds the lock (it may still be starting).",
                details={"state": state},
            )
        self._handle = handle
        # We own the lock, so any existing state file is stale (e.g. after a crash).
        old = read_state(self.state_path)
        if old is not None:
            try:
                self.state_path.unlink()
            except OSError:
                pass

    def write_state(self, info: dict[str, Any]) -> None:
        if self._handle is None:
            raise LockError("Cannot write daemon state without holding the lock")
        write_private_file(self.state_path, json.dumps(info, indent=2) + "\n")

    def release(self) -> None:
        if self._handle is None:
            return
        try:
            state = read_state(self.state_path)
            if state is not None and state.get("pid") == os.getpid():
                self.state_path.unlink()
        except OSError:
            pass
        _unlock(self._handle)
        self._handle.close()
        self._handle = None


def current_process_state(host: str, port: int, version: str) -> dict[str, Any]:
    from datetime import UTC, datetime

    me = psutil.Process(os.getpid())
    return {
        "pid": me.pid,
        "create_time": me.create_time(),
        "host": host,
        "port": port,
        "version": version,
        "started_at": datetime.now(UTC).isoformat(),
        "executable": sys.executable,
    }
