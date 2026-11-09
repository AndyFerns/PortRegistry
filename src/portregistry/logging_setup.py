"""Logging configuration for the daemon."""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path

LOG_FORMAT = "%(asctime)s %(levelname)-7s [%(threadName)s] %(name)s: %(message)s"


class RedactingFilter(logging.Filter):
    """Defence in depth: replace known secrets if they ever reach a log record."""

    def __init__(self, secrets_to_hide: list[str]) -> None:
        super().__init__()
        self._secrets = [s for s in secrets_to_hide if s]

    def filter(self, record: logging.LogRecord) -> bool:
        if not self._secrets:
            return True
        message = record.getMessage()
        redacted = message
        for secret in self._secrets:
            if secret in redacted:
                redacted = redacted.replace(secret, "[REDACTED]")
        if redacted != message:
            record.msg = redacted
            record.args = None
        return True


def configure_logging(
    level: str,
    log_file: Path | None,
    *,
    console: bool,
    secrets_to_hide: list[str] | None = None,
) -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.setLevel(level)
    formatter = logging.Formatter(LOG_FORMAT)
    redactor = RedactingFilter(secrets_to_hide or [])

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(redactor)
        root.addHandler(file_handler)
    if console:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        stream_handler.addFilter(redactor)
        root.addHandler(stream_handler)

    # Keep third-party chatter down; uvicorn's access log is disabled entirely.
    for noisy in ("urllib3", "docker", "asyncio", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").disabled = True
