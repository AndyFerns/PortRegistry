"""Machine and process identity.

* The machine UUID is a random UUID generated once and persisted in the data
  directory. No hardware serials or other sensitive identifiers are used.
* A process instance is identified by machine UUID + PID + process creation
  time. PID alone is never treated as a stable identity because PIDs are reused.
"""

from __future__ import annotations

import hashlib
import platform
import socket
import uuid
from pathlib import Path

from portregistry.paths import write_private_file

#: Creation times are compared at millisecond precision. Two processes cannot
#: share a PID within the same millisecond, and this avoids float jitter.
CREATE_TIME_PRECISION = 3


def load_or_create_machine_id(path: Path) -> uuid.UUID:
    try:
        text = path.read_text(encoding="utf-8").strip()
        if text:
            return uuid.UUID(text)
    except FileNotFoundError:
        pass
    except ValueError:
        # Corrupt file: do not silently invent a new identity over it.
        raise
    machine_id = uuid.uuid4()
    write_private_file(path, str(machine_id) + "\n")
    return machine_id


def machine_facts() -> dict[str, str]:
    return {
        "hostname": socket.gethostname(),
        "os_name": platform.system() or "unknown",
        "os_version": platform.release() or "",
        "os_detail": platform.version() or "",
        "architecture": platform.machine() or "",
    }


def normalize_create_time(create_time: float) -> str:
    return f"{create_time:.{CREATE_TIME_PRECISION}f}"


def process_key(pid: int, create_time: float) -> str:
    """Stable per-machine key for a process instance with a known creation time."""
    return f"{pid}:{normalize_create_time(create_time)}"


def incomplete_process_key(pid: int) -> str:
    """Key for a process whose creation time is unknown.

    A random suffix is used so that the identity is never silently merged with
    a later process that reuses the PID.
    """
    return f"{pid}:incomplete:{uuid.uuid4().hex[:12]}"


def process_identity_hash(machine_uuid: uuid.UUID | str, pid: int, create_time: float) -> str:
    raw = f"{machine_uuid}|{pid}|{normalize_create_time(create_time)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def socket_key(protocol: str, family: str, address: str, port: int, owner_key: str) -> str:
    """Deduplication key for an endpoint owned by a specific process instance."""
    return f"{protocol}|{family}|{address}|{port}|{owner_key}"
