"""Validated local configuration.

Configuration lives in ``config.toml`` inside the config directory (see
:mod:`portregistry.paths`). A commented default file is written the first time
the daemon starts. Environment overrides:

* ``PORTREGISTRY_HOST`` / ``PORTREGISTRY_PORT`` - daemon bind address/port.
"""

from __future__ import annotations

import ipaddress
import os
import secrets
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from portregistry.exceptions import ConfigError
from portregistry.paths import AppPaths, get_paths, write_private_file

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

DEFAULT_CONFIG_TEXT = """\
# PortRegistry configuration.
# Restart the daemon after editing: `portregistry daemon restart`

[daemon]
# Loopback only by default. Binding to a non-loopback address exposes process and
# port inventory to the network and additionally requires allow_remote = true.
host = "127.0.0.1"
port = 8765
allow_remote = false

[discovery]
# Native socket reconciliation interval in seconds (periodic full scan).
native_interval = 10
# Docker discovery is optional; it is skipped gracefully when Docker is unavailable.
docker_enabled = true
docker_interval = 30
# Optional process metadata. Command lines may contain secrets passed as arguments;
# they are stored only in the local database and are never executed.
collect_cmdline = true
collect_username = true
collect_cwd = true
# Data older than native_interval * stale_after_factor is reported as stale.
stale_after_factor = 3

[history]
# History events and inactive observed records older than this are deleted.
# Services and reservations are never deleted by retention cleanup.
retention_days = 30

[logging]
level = "INFO"
"""


@dataclass(frozen=True)
class DaemonConfig:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    allow_remote: bool = False


@dataclass(frozen=True)
class DiscoveryConfig:
    native_interval: float = 10.0
    docker_enabled: bool = True
    docker_interval: float = 30.0
    collect_cmdline: bool = True
    collect_username: bool = True
    collect_cwd: bool = True
    stale_after_factor: float = 3.0


@dataclass(frozen=True)
class HistoryConfig:
    retention_days: int = 30


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"


@dataclass(frozen=True)
class Config:
    paths: AppPaths
    daemon: DaemonConfig = field(default_factory=DaemonConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    history: HistoryConfig = field(default_factory=HistoryConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    @property
    def base_url(self) -> str:
        host = self.daemon.host
        if host in ("0.0.0.0", "::"):
            host = "127.0.0.1"
        if ":" in host:
            host = f"[{host}]"
        return f"http://{host}:{self.daemon.port}"

    def as_public_dict(self) -> dict[str, Any]:
        """Configuration without secrets, suitable for status displays."""
        return {
            "daemon": asdict(self.daemon),
            "discovery": asdict(self.discovery),
            "history": asdict(self.history),
            "logging": asdict(self.logging),
            "paths": self.paths.as_dict(),
        }


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _expect(section: dict[str, Any], key: str, kinds: tuple[type, ...], default: Any) -> Any:
    if key not in section:
        return default
    value = section[key]
    # bool is a subclass of int; do not accept it where a number is expected.
    if isinstance(value, bool) and bool not in kinds:
        raise ConfigError(f"Configuration value '{key}' must be a number, not a boolean.")
    if not isinstance(value, kinds):
        names = " or ".join(k.__name__ for k in kinds)
        raise ConfigError(f"Configuration value '{key}' must be of type {names}.")
    return value


def parse_config(raw: dict[str, Any], paths: AppPaths) -> Config:
    """Validate a raw TOML mapping and build a :class:`Config`."""
    for name in ("daemon", "discovery", "history", "logging"):
        if name in raw and not isinstance(raw[name], dict):
            raise ConfigError(f"Configuration section [{name}] must be a table.")
    d = raw.get("daemon", {})
    disc = raw.get("discovery", {})
    hist = raw.get("history", {})
    log = raw.get("logging", {})

    host = str(_expect(d, "host", (str,), DEFAULT_HOST)).strip()
    port = int(_expect(d, "port", (int,), DEFAULT_PORT))
    allow_remote = bool(_expect(d, "allow_remote", (bool,), False))

    env_host = os.environ.get("PORTREGISTRY_HOST")
    env_port = os.environ.get("PORTREGISTRY_PORT")
    if env_host:
        host = env_host.strip()
    if env_port:
        try:
            port = int(env_port)
        except ValueError as exc:
            raise ConfigError("PORTREGISTRY_PORT must be an integer.") from exc

    if not 1 <= port <= 65535:
        raise ConfigError(f"Daemon port {port} is out of range (1-65535).")
    if host != "localhost":
        try:
            ipaddress.ip_address(host.strip("[]"))
        except ValueError as exc:
            raise ConfigError(
                f"Daemon host '{host}' must be an IP address or 'localhost'."
            ) from exc
    if not is_loopback_host(host) and not allow_remote:
        raise ConfigError(
            f"Refusing to bind the daemon to non-loopback address '{host}'. "
            "This would expose process and port inventory to the network. "
            "Set allow_remote = true in [daemon] if you really want this."
        )

    native_interval = float(_expect(disc, "native_interval", (int, float), 10))
    docker_interval = float(_expect(disc, "docker_interval", (int, float), 30))
    stale_factor = float(_expect(disc, "stale_after_factor", (int, float), 3))
    if native_interval < 2:
        raise ConfigError("discovery.native_interval must be at least 2 seconds.")
    if docker_interval < 5:
        raise ConfigError("discovery.docker_interval must be at least 5 seconds.")
    if stale_factor < 1:
        raise ConfigError("discovery.stale_after_factor must be at least 1.")

    retention = int(_expect(hist, "retention_days", (int,), 30))
    if retention < 1:
        raise ConfigError("history.retention_days must be at least 1.")

    level = str(_expect(log, "level", (str,), "INFO")).upper()
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        raise ConfigError("logging.level must be one of DEBUG, INFO, WARNING, ERROR.")

    return Config(
        paths=paths,
        daemon=DaemonConfig(host=host, port=port, allow_remote=allow_remote),
        discovery=DiscoveryConfig(
            native_interval=native_interval,
            docker_enabled=bool(_expect(disc, "docker_enabled", (bool,), True)),
            docker_interval=docker_interval,
            collect_cmdline=bool(_expect(disc, "collect_cmdline", (bool,), True)),
            collect_username=bool(_expect(disc, "collect_username", (bool,), True)),
            collect_cwd=bool(_expect(disc, "collect_cwd", (bool,), True)),
            stale_after_factor=stale_factor,
        ),
        history=HistoryConfig(retention_days=retention),
        logging=LoggingConfig(level=level),
    )


def load_config(paths: AppPaths | None = None) -> Config:
    """Load and validate the configuration file (defaults if it does not exist)."""
    paths = paths or get_paths()
    raw: dict[str, Any] = {}
    if paths.config_file.exists():
        try:
            raw = tomllib.loads(paths.config_file.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"Cannot read configuration file {paths.config_file}: {exc}") from exc
    return parse_config(raw, paths)


def write_default_config(paths: AppPaths) -> bool:
    """Write the commented default config if none exists. Returns True if written."""
    if paths.config_file.exists():
        return False
    write_private_file(paths.config_file, DEFAULT_CONFIG_TEXT)
    return True


def _read_secret(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConfigError(f"Cannot read {path}: {exc}") from exc
    return value or None


def read_token(paths: AppPaths) -> str | None:
    """Return the local API token, or None if the daemon has never created one."""
    return _read_secret(paths.token_file)


def load_or_create_token(paths: AppPaths) -> str:
    token = read_token(paths)
    if token is None:
        token = secrets.token_urlsafe(32)
        write_private_file(paths.token_file, token + "\n")
    return token


def load_or_create_secret_key(paths: AppPaths) -> str:
    key = _read_secret(paths.secret_key_file)
    if key is None:
        key = secrets.token_urlsafe(50)
        write_private_file(paths.secret_key_file, key + "\n")
    return key
