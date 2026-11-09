"""Server-Sent Events stream of committed state changes.

Events are hints: on connect (and on ``resync``) clients must refetch
authoritative state through the regular API. There is no replay of missed
events; reconnecting clients simply refresh.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

from django.http import HttpRequest, JsonResponse, StreamingHttpResponse

from portregistry.core.application import get_application, has_application
from portregistry.django_app.api.auth import bearer_token, token_is_valid
from portregistry.django_app.api.errors import error_body

HEARTBEAT_SECONDS = 15.0
RETRY_MS = 3000


def _frame(event: str, data: dict[str, object], event_id: int | None = None) -> str:
    lines = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event}")
    lines.append(f"data: {json.dumps(data, separators=(',', ':'), default=str)}")
    return "\n".join(lines) + "\n\n"


async def _authenticated(request: HttpRequest) -> bool:
    header = request.headers.get("Authorization", "")
    if header:
        token = bearer_token(header)
        return token is not None and token_is_valid(token)
    user = await request.auser()
    return bool(user and user.is_authenticated)


async def event_stream(request: HttpRequest) -> StreamingHttpResponse | JsonResponse:
    if request.method != "GET":
        return JsonResponse(error_body("method_not_allowed", "Use GET."), status=405)
    if not await _authenticated(request):
        return JsonResponse(
            error_body("not_authenticated", "Authentication credentials were not provided."),
            status=401,
        )
    if not has_application():
        return JsonResponse(error_body("unavailable", "Daemon not initialised."), status=503)
    app = get_application()
    bus = app.bus
    subscription = bus.subscribe()

    async def stream() -> AsyncIterator[str]:
        try:
            yield f"retry: {RETRY_MS}\n\n"
            yield _frame(
                "hello", {"resync": True, "last_seq": bus.last_seq, "version": app.version}
            )
            while True:
                item = await subscription.get(HEARTBEAT_SECONDS)
                if item is None:
                    yield _frame("daemon", {"type": "daemon.stopping"})
                    break
                if item == "timeout":
                    yield ": heartbeat\n\n"
                    continue
                if subscription.overflowed:
                    subscription.overflowed = False
                    yield _frame("resync", {"reason": "client fell behind; refetch state"})
                assert not isinstance(item, str)
                yield _frame(item.topic, item.as_dict(), item.seq)
        finally:
            bus.unsubscribe(subscription)

    response = StreamingHttpResponse(stream(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return response
