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

[noise]
# UDP sockets on the OS ephemeral port range (short-lived client sockets from
# browsers, DNS resolvers...) are not flagged as unregistered listeners and their
# history events are marked as noise (hidden by default).
ephemeral_udp = true
# An endpoint that closes within this many seconds of opening is "flapping":
# both history events are marked as noise.
flap_window_seconds = 120
# Noise events are deleted sooner than regular history.
noise_retention_days = 3

[logging]
level = "INFO"

# Alerts: POST a JSON payload to your own endpoints when conflicts appear or are
# resolved. Disabled unless at least one webhook is configured. Example:
#
# [[alerts.webhook]]
# url = "http://127.0.0.1:9000/portregistry"
# min_severity = "warning"          # info | warning | error
# events = ["conflict.detected", "conflict.resolved", "docker.unavailable", "scan.failed"]
# secret = "shared-secret"          # optional: adds an HMAC-SHA256 X-PortRegistry-Signature header
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
class NoiseConfig:
    ephemeral_udp: bool = True
    flap_window_seconds: float = 120.0
    noise_retention_days: int = 3


ALERT_EVENTS = (
    "conflict.detected",
    "conflict.resolved",
    "docker.unavailable",
    "docker.available",
    "scan.failed",
    "alert.test",
)
SEVERITY_RANK = {"info": 0, "warning": 1, "error": 2}


@dataclass(frozen=True)
class WebhookConfig:
    url: str
    min_severity: str = "warning"
    events: tuple[str, ...] = ALERT_EVENTS
    secret: str = field(default="", repr=False)

    def public_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "min_severity": self.min_severity,
            "events": list(self.events),
            "signed": bool(self.secret),
        }


@dataclass(frozen=True)
class AlertsConfig:
    webhooks: tuple[WebhookConfig, ...] = ()


@dataclass(frozen=True)
class Config:
    paths: AppPaths
    daemon: DaemonConfig = field(default_factory=DaemonConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    history: HistoryConfig = field(default_factory=HistoryConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    noise: NoiseConfig = field(default_factory=NoiseConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)

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
            "noise": asdict(self.noise),
            "alerts": {"webhooks": [w.public_dict() for w in self.alerts.webhooks]},
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
    for name in ("daemon", "discovery", "history", "logging", "noise", "alerts"):
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

    noise = _parse_noise(raw.get("noise", {}))
    alerts = _parse_alerts(raw.get("alerts", {}))

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
        noise=noise,
        alerts=alerts,
    )


def _parse_noise(section: dict[str, Any]) -> NoiseConfig:
    flap = float(_expect(section, "flap_window_seconds", (int, float), 120))
    keep = int(_expect(section, "noise_retention_days", (int,), 3))
    if flap < 0:
        raise ConfigError("noise.flap_window_seconds must be 0 or more (0 disables).")
    if keep < 1:
        raise ConfigError("noise.noise_retention_days must be at least 1.")
    return NoiseConfig(
        ephemeral_udp=bool(_expect(section, "ephemeral_udp", (bool,), True)),
        flap_window_seconds=flap,
        noise_retention_days=keep,
    )


def _parse_alerts(section: dict[str, Any]) -> AlertsConfig:
    raw_hooks = section.get("webhook", [])
    if isinstance(raw_hooks, dict):
        raw_hooks = [raw_hooks]
    if not isinstance(raw_hooks, list):
        raise ConfigError("alerts.webhook must be an array of tables ([[alerts.webhook]]).")
    hooks: list[WebhookConfig] = []
    for index, hook in enumerate(raw_hooks):
        if not isinstance(hook, dict):
            raise ConfigError(f"alerts.webhook[{index}] must be a table.")
        url = str(_expect(hook, "url", (str,), "")).strip()
        if not url.lower().startswith(("http://", "https://")):
            raise ConfigError(f"alerts.webhook[{index}].url must be an http(s) URL.")
        severity = str(_expect(hook, "min_severity", (str,), "warning")).lower()
        if severity not in SEVERITY_RANK:
            raise ConfigError(
                f"alerts.webhook[{index}].min_severity must be info, warning or error."
            )
        events = _expect(hook, "events", (list,), list(ALERT_EVENTS))
        unknown = [e for e in events if e not in ALERT_EVENTS]
        if unknown or not all(isinstance(e, str) for e in events):
            raise ConfigError(
                f"alerts.webhook[{index}].events contains unknown events {unknown}; "
                f"allowed: {', '.join(ALERT_EVENTS)}."
            )
        secret = str(_expect(hook, "secret", (str,), ""))
        hooks.append(
            WebhookConfig(url=url, min_severity=severity, events=tuple(events), secret=secret)
        )
    return AlertsConfig(webhooks=tuple(hooks))


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


def rotate_token(paths: AppPaths) -> str:
    """Replace the local API token with a new random one (returned, never logged)."""
    token = secrets.token_urlsafe(32)
    write_private_file(paths.token_file, token + "\n")
    return token


def load_or_create_secret_key(paths: AppPaths) -> str:
    key = _read_secret(paths.secret_key_file)
    if key is None:
        key = secrets.token_urlsafe(50)
        write_private_file(paths.secret_key_file, key + "\n")
    return key
