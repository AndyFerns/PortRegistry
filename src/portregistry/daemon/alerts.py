"""Outbound alert webhooks.

Fed by the in-process event bus (topic ``alerts``) after database commits. A
single worker thread delivers JSON payloads so writers are never blocked.
Webhooks are opt-in (configured in ``config.toml``); secrets are never logged.

Payload::

    {"source": "portregistry", "version": "0.2.0", "event": "conflict.detected",
     "severity": "warning", "timestamp": "...", "machine": {"hostname": "...", "uuid": "..."},
     "data": {...}}

With a secret, ``X-PortRegistry-Signature: sha256=<hex HMAC-SHA256 of the body>``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import queue
import socket
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx

from portregistry import __version__
from portregistry.config import SEVERITY_RANK, WebhookConfig
from portregistry.core.events import BusEvent

logger = logging.getLogger(__name__)

MAX_QUEUE = 1000
RETRY_DELAYS = (1.0, 2.0, 4.0)
TIMEOUT = 5.0


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def build_payload(
    event_type: str, severity: str, data: dict[str, Any], machine_uuid: str
) -> dict[str, Any]:
    return {
        "source": "portregistry",
        "version": __version__,
        "event": event_type,
        "severity": severity,
        "timestamp": datetime.now(UTC).isoformat(),
        "machine": {"hostname": socket.gethostname(), "uuid": machine_uuid},
        "data": data,
    }


def wants(hook: WebhookConfig, event_type: str, severity: str) -> bool:
    if event_type not in hook.events:
        return False
    if event_type == "alert.test":
        return True
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(hook.min_severity, 1)


def _redacted(url: str) -> str:
    """Log-safe URL: no query string or credentials (they may carry tokens)."""
    try:
        parsed = httpx.URL(url)
        return f"{parsed.scheme}://{parsed.host}{':' + str(parsed.port) if parsed.port else ''}{parsed.path}"
    except Exception:
        return "<webhook>"


def deliver(
    hook: WebhookConfig,
    payload: dict[str, Any],
    *,
    client: httpx.Client | None = None,
    retries: tuple[float, ...] = RETRY_DELAYS,
    wait: Callable[[float], bool] | None = None,
) -> dict[str, Any]:
    """POST one payload to one webhook with retries. Returns a delivery report."""
    body = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": f"portregistry/{__version__}"}
    if hook.secret:
        headers["X-PortRegistry-Signature"] = sign(hook.secret, body)
    own = client is None
    http = client or httpx.Client(timeout=TIMEOUT, follow_redirects=False)
    error = ""
    try:
        for attempt in range(len(retries) + 1):
            try:
                response = http.post(hook.url, content=body, headers=headers)
                if response.status_code < 300:
                    return {
                        "url": _redacted(hook.url),
                        "ok": True,
                        "status": response.status_code,
                        "attempts": attempt + 1,
                    }
                error = f"HTTP {response.status_code}"
                if 400 <= response.status_code < 500 and response.status_code != 429:
                    break  # client error: retrying will not help
            except httpx.HTTPError as exc:
                error = exc.__class__.__name__
            if attempt < len(retries):
                stopped = (
                    wait(retries[attempt]) if wait else threading.Event().wait(retries[attempt])
                )
                if stopped:
                    break
    finally:
        if own:
            http.close()
    logger.warning("Alert webhook %s failed: %s", _redacted(hook.url), error)
    return {"url": _redacted(hook.url), "ok": False, "error": error}


class AlertDispatcher:
    def __init__(self, webhooks: tuple[WebhookConfig, ...], machine_uuid: str) -> None:
        self.webhooks = webhooks
        self.machine_uuid = machine_uuid
        self._queue: queue.Queue[tuple[str, str, dict[str, Any]] | None] = queue.Queue(
            maxsize=MAX_QUEUE
        )
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.delivered = 0
        self.failed = 0
        self.dropped = 0

    @property
    def enabled(self) -> bool:
        return bool(self.webhooks)

    def start(self) -> None:
        if not self.enabled:
            return
        self._thread = threading.Thread(target=self._run, name="pr-alerts", daemon=True)
        self._thread.start()
        logger.info("Alert webhooks enabled (%d configured)", len(self.webhooks))

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        if self._thread is not None:
            self._thread.join(timeout)

    def on_bus_event(self, event: BusEvent) -> None:
        """Bus listener (called on the publishing thread): enqueue, never block."""
        if not self.enabled or event.topic != "alerts" or self._stop.is_set():
            return
        severity = str(event.data.get("severity", "info"))
        try:
            self._queue.put_nowait((event.type, severity, dict(event.data)))
        except queue.Full:
            self.dropped += 1

    def _run(self) -> None:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as client:
            while not self._stop.is_set():
                item = self._queue.get()
                if item is None:
                    break
                event_type, severity, data = item
                payload = build_payload(event_type, severity, data, self.machine_uuid)
                for hook in self.webhooks:
                    if not wants(hook, event_type, severity):
                        continue
                    report = deliver(hook, payload, client=client, wait=self._stop.wait)
                    if report["ok"]:
                        self.delivered += 1
                    else:
                        self.failed += 1

    def send_test(self) -> list[dict[str, Any]]:
        """Synchronously deliver a test event to every webhook (for `alerts test`)."""
        payload = build_payload(
            "alert.test", "info", {"message": "PortRegistry webhook test"}, self.machine_uuid
        )
        return [
            deliver(hook, payload, retries=())
            for hook in self.webhooks
            if wants(hook, "alert.test", "info")
        ]

    def describe(self) -> dict[str, Any]:
        return {
            "webhooks": [h.public_dict() for h in self.webhooks],
            "delivered": self.delivered,
            "failed": self.failed,
            "dropped": self.dropped,
            "queued": self._queue.qsize(),
        }
