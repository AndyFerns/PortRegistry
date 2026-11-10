"""Operating-system access for process control (look up, verify identity, signal).

Everything that touches live processes for "Stop process" lives here behind the
:class:`ProcessOs` protocol so the decision logic in
:mod:`portregistry.services.process_control` can be tested with fakes.

Identity is always re-verified against the live OS immediately before acting,
and the process is pinned while it is signalled so a reused PID can never be hit:

* Windows: ``OpenProcess`` returns a handle that keeps the PID from being reused;
  the creation time is checked through that handle (``GetProcessTimes``) before
  ``TerminateProcess`` or a polite ``WM_CLOSE`` to the process's own windows.
* Linux: ``pidfd_open`` pins the process; the creation time is checked, then
  ``pidfd_send_signal`` delivers the signal and the pidfd is polled for exit.
* macOS/other POSIX: psutil's ``send_signal`` re-checks PID + creation time just
  before ``kill()``. A tiny window remains between that check and the signal.

Nothing here executes command lines, reads environment variables or elevates.
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

import psutil

#: Creation times are compared with this tolerance (identity keys use milliseconds).
CREATE_TIME_TOLERANCE = 0.002

#: Stop methods. ``graceful`` = SIGTERM (POSIX) or WM_CLOSE to the process's
#: windows (Windows); ``immediate`` = Windows TerminateProcess because no polite
#: close exists for that process; ``forced`` = SIGKILL / TerminateProcess chosen
#: explicitly by the user.
METHODS = ("graceful", "immediate", "forced")


class ProcessGone(Exception):
    """The process has already exited."""


class IdentityChanged(Exception):
    """The PID now belongs to a different process (creation time differs)."""


class AccessDenied(Exception):
    """The OS refused access to the process."""


class NothingToClose(Exception):
    """A polite close was requested but the process has no window to close."""


@dataclass(frozen=True)
class LiveProcess:
    pid: int
    create_time: float | None
    name: str = ""
    exe: str = ""
    cmdline: tuple[str, ...] = ()
    username: str | None = None
    uid: int | None = None
    ppid: int | None = None
    cwd: str = ""

    def matches(self, create_time: float | None) -> bool:
        if create_time is None or self.create_time is None:
            return False
        return abs(self.create_time - create_time) < CREATE_TIME_TOLERANCE


class OpenedProcess(Protocol):
    def send(self, method: str) -> None: ...

    def wait(self, timeout: float) -> bool: ...

    def close(self) -> None: ...


class ProcessOs(Protocol):
    platform: str  # windows | linux | macos

    def lookup(self, pid: int) -> LiveProcess | None: ...

    def descendants(self, pid: int) -> list[int]: ...

    def has_visible_window(self, pid: int) -> bool: ...

    def service_pids(self) -> frozenset[int]: ...

    def daemon_pid(self) -> int: ...

    def is_elevated(self) -> bool | None: ...

    def open(self, pid: int, create_time: float) -> OpenedProcess: ...


def current_platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


# ----------------------------------------------------------------- psutil reads


def _safe(fn: Callable[[], Any], default: Any) -> Any:
    try:
        return fn()
    except (psutil.Error, OSError):
        return default


def snapshot(proc: psutil.Process) -> LiveProcess:
    """Read the live metadata needed for a stop decision (never the environment)."""
    uids = _safe(proc.uids, None) if hasattr(proc, "uids") else None
    return LiveProcess(
        pid=proc.pid,
        create_time=_safe(proc.create_time, None),
        name=_safe(proc.name, "") or "",
        exe=_safe(proc.exe, "") or "",
        cmdline=tuple(_safe(proc.cmdline, []) or []),
        username=_safe(proc.username, None),
        uid=getattr(uids, "real", None) if uids is not None else None,
        ppid=_safe(proc.ppid, None),
        cwd=_safe(proc.cwd, "") or "",
    )


class PsutilProcessOs:
    """The real OS adapter."""

    def __init__(self) -> None:
        self.platform = current_platform()
        self._services_lock = threading.Lock()
        self._services: tuple[float, frozenset[int]] | None = None

    def lookup(self, pid: int) -> LiveProcess | None:
        try:
            return snapshot(psutil.Process(pid))
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None
        except psutil.Error:
            return LiveProcess(pid=pid, create_time=None)

    def descendants(self, pid: int) -> list[int]:
        try:
            return [c.pid for c in psutil.Process(pid).children(recursive=True)]
        except psutil.Error:
            return []

    def has_visible_window(self, pid: int) -> bool:
        if self.platform != "windows":
            return False
        return bool(_windows_top_level_windows(pid))

    def service_pids(self) -> frozenset[int]:
        """PIDs of running Windows services (cached for 60 s). Empty elsewhere."""
        if self.platform != "windows":
            return frozenset()
        with self._services_lock:
            now = time.monotonic()
            if self._services is not None and now - self._services[0] < 60:
                return self._services[1]
            pids: set[int] = set()
            try:
                for svc in getattr(psutil, "win_service_iter")():  # noqa: B009 - Windows only
                    pid = _safe(svc.pid, None)
                    if pid:
                        pids.add(int(pid))
            except (psutil.Error, OSError, AttributeError):
                pass
            self._services = (now, frozenset(pids))
            return self._services[1]

    def daemon_pid(self) -> int:
        return os.getpid()

    def is_elevated(self) -> bool | None:
        from portregistry.discovery.providers.platform_notes import is_elevated

        return is_elevated()

    def open(self, pid: int, create_time: float) -> OpenedProcess:
        if self.platform == "windows":
            return _WindowsOpened(pid, create_time)
        if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
            return _PidfdOpened(pid, create_time)
        return _PsutilOpened(pid, create_time)


# ---------------------------------------------------------------------- Windows

_PROCESS_TERMINATE = 0x0001
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x00100000
_ERROR_ACCESS_DENIED = 5
_ERROR_INVALID_PARAMETER = 87
_WAIT_OBJECT_0 = 0
_WM_CLOSE = 0x0010
_GW_OWNER = 4
_EPOCH_AS_FILETIME = 116444736000000000


def _win32() -> tuple[Any, Any, Any]:
    import ctypes
    from ctypes import wintypes

    win_dll = getattr(ctypes, "WinDLL")  # noqa: B009 - Windows-only attribute
    k32 = win_dll("kernel32", use_last_error=True)
    u32 = win_dll("user32", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    k32.GetProcessTimes.restype = wintypes.BOOL
    k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k32.TerminateProcess.restype = wintypes.BOOL
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.WaitForSingleObject.restype = wintypes.DWORD
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    u32.IsWindowVisible.argtypes = [wintypes.HWND]
    u32.IsWindowVisible.restype = wintypes.BOOL
    u32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
    u32.GetWindow.restype = wintypes.HWND
    u32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    u32.GetWindowThreadProcessId.restype = wintypes.DWORD
    u32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    u32.PostMessageW.restype = wintypes.BOOL
    return ctypes, k32, u32


def _windows_top_level_windows(pid: int) -> list[int]:
    """Visible, unowned top-level windows belonging to ``pid``."""
    ctypes, _k32, u32 = _win32()
    from ctypes import wintypes

    found: list[int] = []
    enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def callback(hwnd: Any, _lparam: Any) -> bool:
        if u32.IsWindowVisible(hwnd) and not u32.GetWindow(hwnd, _GW_OWNER):
            owner = wintypes.DWORD()
            u32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
            if owner.value == pid:
                found.append(hwnd)
        return True

    u32.EnumWindows(enum_proc(callback), 0)
    return found


class _WindowsOpened:
    def __init__(self, pid: int, create_time: float) -> None:
        ctypes, k32, _u32 = _win32()
        from ctypes import wintypes

        self._ctypes, self._k32, self.pid = ctypes, k32, pid
        access = _PROCESS_TERMINATE | _PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE
        handle = k32.OpenProcess(access, False, pid)
        if not handle:
            err = ctypes.get_last_error()
            if err == _ERROR_INVALID_PARAMETER:
                raise ProcessGone(pid)
            if err == _ERROR_ACCESS_DENIED:
                raise AccessDenied(pid)
            raise OSError(err, f"OpenProcess failed for PID {pid}")
        self._handle = handle
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if not k32.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
                raise AccessDenied(pid)
            raw = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            actual = (raw - _EPOCH_AS_FILETIME) / 1e7
            if abs(actual - create_time) >= CREATE_TIME_TOLERANCE:
                raise IdentityChanged(pid)
            if k32.WaitForSingleObject(handle, 0) == _WAIT_OBJECT_0:
                raise ProcessGone(pid)
        except BaseException:
            self.close()
            raise

    def send(self, method: str) -> None:
        if method == "graceful":
            # The handle stays open, so the PID cannot be reused while we look up
            # and message the process's windows.
            windows = _windows_top_level_windows(self.pid)
            if not windows:
                raise NothingToClose(self.pid)
            _ctypes, _k32, u32 = _win32()
            for hwnd in windows:
                u32.PostMessageW(hwnd, _WM_CLOSE, 0, 0)
            return
        if not self._k32.TerminateProcess(self._handle, 1):
            err = self._ctypes.get_last_error()
            if err == _ERROR_ACCESS_DENIED:
                raise AccessDenied(self.pid)
            raise OSError(err, f"TerminateProcess failed for PID {self.pid}")

    def wait(self, timeout: float) -> bool:
        ms = max(0, int(timeout * 1000))
        return bool(self._k32.WaitForSingleObject(self._handle, ms) == _WAIT_OBJECT_0)

    def close(self) -> None:
        handle, self._handle = getattr(self, "_handle", None), None
        if handle:
            self._k32.CloseHandle(handle)


# ------------------------------------------------------------------------- POSIX


def _posix_signal(method: str) -> int:
    if method == "forced":
        return int(getattr(signal, "SIGKILL", signal.SIGTERM))
    return int(signal.SIGTERM)


def _verify(pid: int, create_time: float) -> psutil.Process:
    try:
        proc = psutil.Process(pid)
        actual = proc.create_time()
    except psutil.NoSuchProcess as exc:
        raise ProcessGone(pid) from exc
    except psutil.AccessDenied as exc:
        raise AccessDenied(pid) from exc
    if abs(actual - create_time) >= CREATE_TIME_TOLERANCE:
        raise IdentityChanged(pid)
    if _safe(proc.status, "") == psutil.STATUS_ZOMBIE:
        raise ProcessGone(pid)
    return proc


class _PidfdOpened:
    """Linux: the pidfd refers to this exact process for its whole lifetime."""

    def __init__(self, pid: int, create_time: float) -> None:
        self.pid = pid
        try:
            self._fd: int | None = getattr(os, "pidfd_open")(pid)  # noqa: B009 - Linux only
        except ProcessLookupError as exc:
            raise ProcessGone(pid) from exc
        except PermissionError as exc:
            raise AccessDenied(pid) from exc
        try:
            # Verified *after* pinning: if the PID was reused before pidfd_open,
            # the creation time no longer matches and we refuse.
            _verify(pid, create_time)
        except BaseException:
            self.close()
            raise

    def send(self, method: str) -> None:
        assert self._fd is not None
        try:
            send = getattr(signal, "pidfd_send_signal")  # noqa: B009 - Linux only
            send(self._fd, _posix_signal(method))
        except ProcessLookupError as exc:
            raise ProcessGone(self.pid) from exc
        except PermissionError as exc:
            raise AccessDenied(self.pid) from exc

    def wait(self, timeout: float) -> bool:
        import select

        assert self._fd is not None
        poller = getattr(select, "poll")()  # noqa: B009 - POSIX only
        poller.register(self._fd, getattr(select, "POLLIN"))  # noqa: B009
        return bool(poller.poll(max(0, int(timeout * 1000))))

    def close(self) -> None:
        fd, self._fd = getattr(self, "_fd", None), None
        if fd is not None:
            os.close(fd)


class _PsutilOpened:
    """macOS/other POSIX: psutil re-checks PID + creation time before kill()."""

    def __init__(self, pid: int, create_time: float) -> None:
        self.pid = pid
        self._proc = _verify(pid, create_time)

    def send(self, method: str) -> None:
        try:
            self._proc.send_signal(_posix_signal(method))
        except psutil.NoSuchProcess as exc:
            raise ProcessGone(self.pid) from exc
        except psutil.AccessDenied as exc:
            raise AccessDenied(self.pid) from exc

    def wait(self, timeout: float) -> bool:
        try:
            self._proc.wait(timeout=max(0.0, timeout))
        except psutil.TimeoutExpired:
            return False
        except psutil.Error:
            return True
        return True

    def close(self) -> None:
        return None


@dataclass
class _AdapterBox:
    adapter: ProcessOs | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


_box = _AdapterBox()


def default_os() -> ProcessOs:
    with _box.lock:
        if _box.adapter is None:
            _box.adapter = PsutilProcessOs()
        return _box.adapter
