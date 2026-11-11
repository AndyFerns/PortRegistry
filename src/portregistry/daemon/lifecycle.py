"""Daemon startup and shutdown sequence (foreground process).

Order of operations:

1. Paths, default config, API token, Django secret key.
2. Logging (token redacted).
3. Single-instance lock (``daemon.lock``); refuse duplicate startup.
4. Port availability check.
5. ``django.setup()`` + migrations (WAL mode, foreign keys, busy timeout).
6. Machine identity, owner user, interrupted-scan cleanup.
7. Initial native discovery and Docker inventory.
8. Scheduler and Docker event listener.
9. Uvicorn (single worker) until SIGINT/SIGTERM or API shutdown.
10. Shutdown: close SSE streams, stop scheduler and Docker stream, record the
    machine going offline, close DB connections, release the lock.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
from typing import Any

from portregistry import __version__
from portregistry.config import (
    Config,
    is_loopback_host,
    load_config,
    load_or_create_secret_key,
    load_or_create_token,
    write_default_config,
)
from portregistry.daemon.lock import DaemonLock, current_process_state
from portregistry.exceptions import ConfigError, DaemonAlreadyRunningError, LockError
from portregistry.logging_setup import configure_logging
from portregistry.paths import AppPaths, ensure_dirs, get_paths

logger = logging.getLogger("portregistry.daemon")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2
EXIT_ALREADY_RUNNING = 3
EXIT_PORT_IN_USE = 4


def port_available(host: str, port: int) -> bool:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        if sys.platform != "win32":
            # Match uvicorn: allow rebinding over TIME_WAIT on POSIX. On Windows
            # SO_REUSEADDR would allow stealing a port that is in use.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def run_daemon(*, console: bool = True) -> int:
    paths = get_paths()
    try:
        ensure_dirs(paths)
        write_default_config(paths)
        config = load_config(paths)
        token = load_or_create_token(paths)
        load_or_create_secret_key(paths)
    except ConfigError as exc:
        print(f"PortRegistry configuration error: {exc.message}", file=sys.stderr)
        return EXIT_CONFIG
    except OSError as exc:
        print(f"PortRegistry cannot initialise its data directories: {exc}", file=sys.stderr)
        return EXIT_ERROR

    configure_logging(
        config.logging.level, paths.log_file, console=console, secrets_to_hide=[token]
    )
    logger.info("PortRegistry %s starting (pid %d)", __version__, os.getpid())
    if not is_loopback_host(config.daemon.host):
        logger.warning(
            "SECURITY WARNING: binding to non-loopback address %s. Process and port inventory "
            "will be reachable from the network (token/session authentication still applies).",
            config.daemon.host,
        )

    lock = DaemonLock(paths.lock_file, paths.state_file)
    try:
        lock.acquire()
    except DaemonAlreadyRunningError as exc:
        logger.error("%s", exc.message)
        return EXIT_ALREADY_RUNNING
    except LockError as exc:
        logger.error("%s", exc.message)
        return EXIT_ERROR

    try:
        if not port_available(config.daemon.host, config.daemon.port):
            logger.error(
                "Port %s:%d is already in use by another program. Choose another port with "
                "PORTREGISTRY_PORT or [daemon] port in %s.",
                config.daemon.host,
                config.daemon.port,
                paths.config_file,
            )
            return EXIT_PORT_IN_USE
        return _run_locked(config, paths, token, lock)
    except Exception:
        logger.exception("PortRegistry daemon crashed")
        return EXIT_ERROR
    finally:
        lock.release()
        logger.info("PortRegistry daemon stopped")


def _run_locked(config: Config, paths: AppPaths, token: str, lock: DaemonLock) -> int:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "portregistry.django_app.settings")
    import django

    django.setup()

    from django.core.asgi import get_asgi_application
    from django.core.management import call_command
    from django.db import connections

    from portregistry.core.application import Application, set_application
    from portregistry.core.identity import load_or_create_machine_id
    from portregistry.core.types import ScanScope
    from portregistry.daemon.alerts import AlertDispatcher
    from portregistry.daemon.scheduler import Scheduler
    from portregistry.daemon.server import build_server
    from portregistry.discovery.coordinator import DiscoveryCoordinator
    from portregistry.discovery.docker.provider import DockerProvider
    from portregistry.discovery.process_resolver import ProcessResolver
    from portregistry.discovery.providers.platform_notes import platform_capabilities
    from portregistry.discovery.providers.psutil_provider import PsutilProvider
    from portregistry.django_app.api.auth import ensure_owner_user
    from portregistry.services.conflict_store import refresh_conflicts
    from portregistry.services.docker_state import DockerDiscoveryService
    from portregistry.services.history import cleanup
    from portregistry.services.machines import ensure_local_machine, set_machine_online
    from portregistry.services.reconcile import fail_interrupted_scans
    from portregistry.services.scanning import NativeScanStore

    logger.info("Database: %s", paths.database)
    call_command("migrate", interactive=False, verbosity=0)

    machine_uuid = load_or_create_machine_id(paths.machine_id_file)
    app = Application(
        config=config,
        token=token,
        machine_uuid=machine_uuid,
        platform_info=platform_capabilities(),
    )
    if not config.discovery.docker_enabled:
        app.docker_provider.enabled = False
        app.docker_provider.update("disabled", "Docker discovery disabled in configuration")
    app.alerts = AlertDispatcher(config.alerts.webhooks, str(machine_uuid))
    app.bus.add_listener(app.alerts.on_bus_event)
    app.alerts.start()
    set_application(app)
    _log_control_state(config, app.platform_info.get("elevated"))

    machine = ensure_local_machine(machine_uuid)
    logger.info("Machine %s (%s)", machine.hostname, machine.uuid)
    interrupted = fail_interrupted_scans(machine)
    if interrupted:
        logger.info("Marked %d interrupted scans from a previous run as failed", interrupted)
    ensure_owner_user()
    set_machine_online(machine, True)

    d = config.discovery
    provider = PsutilProvider(
        ProcessResolver(
            collect_cmdline=d.collect_cmdline,
            collect_username=d.collect_username,
            collect_cwd=d.collect_cwd,
        )
    )
    coordinator = DiscoveryCoordinator(provider, NativeScanStore(machine, app))

    docker_service: DockerDiscoveryService | None = None
    if d.docker_enabled:
        docker_service = DockerDiscoveryService(app, machine, DockerProvider())

    logger.info("Running initial discovery")
    app.conflicts_ready = False  # compute conflicts once both providers have reported
    summary = coordinator.run_native_scan(ScanScope.build(), "initial")
    if summary is not None:
        logger.info(
            "Initial discovery: %s, %d endpoints, %d processes",
            summary.status,
            summary.socket_count,
            summary.process_count,
        )
    if docker_service is not None:
        docker_summary = docker_service.reconcile("initial")
        if docker_summary.available:
            logger.info("Docker: %d containers", docker_summary.containers)
        else:
            logger.info("Docker unavailable: %s", docker_summary.error)
    app.conflicts_ready = True
    refresh_conflicts(machine)

    retention = config.history.retention_days
    scheduler = Scheduler(
        native_runner=coordinator.run_native_scan,
        native_interval=d.native_interval,
        docker_runner=docker_service.reconcile if docker_service else None,
        docker_interval=d.docker_interval if docker_service else None,
        maintenance_runner=lambda: cleanup(
            retention, noise_retention_days=config.noise.noise_retention_days
        ),
    )
    app.scheduler = scheduler
    scheduler.start()
    if docker_service is not None:
        docker_service.start_listener(scheduler.request_docker_refresh)

    def on_exit() -> None:
        app.shutting_down = True
        app.bus.close()
        scheduler.signal_stop()

    server = build_server(get_asgi_application(), config.daemon.host, config.daemon.port, on_exit)
    app.set_shutdown_callback(server.request_shutdown)
    lock.write_state(current_process_state(config.daemon.host, config.daemon.port, __version__))
    logger.info(
        "PortRegistry daemon listening on %s (API %s/api/v1/)", config.base_url, config.base_url
    )

    exit_code = EXIT_OK
    try:
        server.run()
        if not server.started:
            exit_code = EXIT_ERROR
    except SystemExit as exc:  # uvicorn exits on bind failures
        exit_code = int(exc.code) if isinstance(exc.code, int) else EXIT_ERROR
    finally:
        _shutdown(app, scheduler, docker_service, machine, set_machine_online)
        connections.close_all()
        set_application(None)
    return exit_code


def _shutdown(
    app: Any, scheduler: Any, docker_service: Any, machine: Any, set_machine_online: Any
) -> None:
    logger.info("Shutting down: stopping scheduler and providers")
    app.shutting_down = True
    app.bus.close()
    if not scheduler.stop(timeout=20):
        logger.warning("Scheduler did not stop within 20s; a scan may have been interrupted")
    if docker_service is not None:
        docker_service.stop()
    if getattr(app, "alerts", None) is not None:
        app.alerts.stop()
    try:
        set_machine_online(machine, False, reason="daemon shutdown")
    except Exception:
        logger.exception("Could not record daemon shutdown")


def _log_control_state(config: Config, elevated: bool | None) -> None:
    """Make the process-control posture visible in the daemon log at startup."""
    ctl = config.control
    if not ctl.enabled:
        logger.info("Process control (Stop process) is off")
        return
    if not is_loopback_host(config.daemon.host):
        logger.warning(
            "Process control is configured but FORCED OFF: the daemon listens on a "
            "non-loopback address (%s)",
            config.daemon.host,
        )
        return
    logger.warning(
        "Process control is ON: your own processes can be stopped from the GUI, CLI and TUI "
        "after a two-step confirmation. Every attempt is recorded in history."
    )
    if ctl.allow_other_users and elevated is True:
        logger.warning(
            "SECURITY WARNING: the daemon is elevated and [control] allow_other_users = true. "
            "OTHER USERS' processes can be stopped by anyone holding the API token or a "
            "browser session. Turn this off unless you need it."
        )
    elif ctl.allow_other_users:
        logger.warning(
            "[control] allow_other_users is set but ignored because the daemon is not elevated"
        )
