"""Uvicorn server wrapper: one process, one worker, graceful shutdown hooks."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import uvicorn

logger = logging.getLogger(__name__)


class DaemonServer(uvicorn.Server):
    """Uvicorn server that notifies the daemon as soon as shutdown begins.

    Long-lived SSE responses would otherwise keep the server waiting; the hook
    closes the event bus (ending SSE streams) and stops the scheduler.
    """

    def __init__(self, config: uvicorn.Config, on_exit: Callable[[], None]) -> None:
        super().__init__(config)
        self._on_exit = on_exit
        self._exit_notified = False

    def _notify_exit(self) -> None:
        if not self._exit_notified:
            self._exit_notified = True
            try:
                self._on_exit()
            except Exception:  # pragma: no cover - defensive
                logger.exception("Shutdown hook failed")

    def handle_exit(self, sig: int, frame: Any) -> None:
        logger.info("Received signal %s; shutting down", sig)
        self._notify_exit()
        super().handle_exit(sig, frame)

    def request_shutdown(self) -> None:
        """Thread-safe shutdown request (used by the API shutdown endpoint)."""
        self._notify_exit()
        self.should_exit = True


def build_server(app: Any, host: str, port: int, on_exit: Callable[[], None]) -> DaemonServer:
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        workers=1,
        lifespan="off",  # Django does not implement the ASGI lifespan protocol
        access_log=False,  # never log request URLs (login links carry one-time nonces)
        log_config=None,  # keep PortRegistry's logging configuration
        timeout_graceful_shutdown=5,
        ws="none",
        server_header=False,
        date_header=True,
    )
    return DaemonServer(config, on_exit)
