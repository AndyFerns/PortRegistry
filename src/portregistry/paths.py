"""OS-appropriate locations for PortRegistry configuration, data and logs.

By default the platformdirs conventions are used:

* Windows: ``%LOCALAPPDATA%\\portregistry`` (config + data) and ``...\\portregistry\\Logs``
* Linux:   ``~/.config/portregistry``, ``~/.local/share/portregistry``, ``~/.local/state/portregistry/log``
* macOS:   ``~/Library/Application Support/portregistry`` and ``~/Library/Logs/portregistry``

Setting ``PORTREGISTRY_HOME`` places everything under a single directory, which
is used for tests, demos and running several isolated instances.

Importing this module has no side effects; directories are only created by
:func:`ensure_dirs`.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

import platformdirs

from portregistry import APP_NAME

HOME_ENV = "PORTREGISTRY_HOME"


@dataclass(frozen=True)
class AppPaths:
    config_dir: Path
    data_dir: Path
    log_dir: Path

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.toml"

    @property
    def token_file(self) -> Path:
        return self.config_dir / "token"

    @property
    def secret_key_file(self) -> Path:
        return self.data_dir / "secret_key"

    @property
    def machine_id_file(self) -> Path:
        return self.data_dir / "machine_id"

    @property
    def database(self) -> Path:
        return self.data_dir / "portregistry.sqlite3"

    @property
    def lock_file(self) -> Path:
        return self.data_dir / "daemon.lock"

    @property
    def state_file(self) -> Path:
        return self.data_dir / "daemon.json"

    @property
    def log_file(self) -> Path:
        return self.log_dir / "daemon.log"

    @property
    def bootstrap_log_file(self) -> Path:
        """Captures stdout/stderr of a detached daemon before logging is configured."""
        return self.log_dir / "daemon-bootstrap.log"

    def as_dict(self) -> dict[str, str]:
        return {
            "config_dir": str(self.config_dir),
            "data_dir": str(self.data_dir),
            "log_dir": str(self.log_dir),
            "config_file": str(self.config_file),
            "token_file": str(self.token_file),
            "database": str(self.database),
            "log_file": str(self.log_file),
            "state_file": str(self.state_file),
        }


def get_paths() -> AppPaths:
    """Resolve paths, honouring ``PORTREGISTRY_HOME`` when set."""
    home = os.environ.get(HOME_ENV)
    if home:
        root = Path(home).expanduser().resolve()
        return AppPaths(config_dir=root / "config", data_dir=root / "data", log_dir=root / "logs")
    return AppPaths(
        config_dir=Path(platformdirs.user_config_dir(APP_NAME, appauthor=False)),
        data_dir=Path(platformdirs.user_data_dir(APP_NAME, appauthor=False)),
        log_dir=Path(platformdirs.user_log_dir(APP_NAME, appauthor=False)),
    )


def ensure_dirs(paths: AppPaths) -> None:
    """Create the directories, restricting permissions to the current user on POSIX."""
    for directory in (paths.config_dir, paths.data_dir, paths.log_dir):
        directory.mkdir(parents=True, exist_ok=True)
        if sys.platform != "win32":
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass


def write_private_file(path: Path, content: str) -> None:
    """Atomically write ``content`` to ``path`` readable only by the current user.

    On POSIX the file mode is 0600. On Windows the file inherits the ACL of the
    per-user profile directory it lives in.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    os.replace(tmp, path)
    if sys.platform != "win32":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
