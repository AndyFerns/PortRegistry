"""Consistent JSON error responses: ``{"error": {"code", "message", "details"}}``."""

from __future__ import annotations

import logging
from typing import Any

from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404, HttpRequest, JsonResponse
from rest_framework import exceptions as drf
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler

from portregistry.exceptions import NotFoundError, PortRegistryError, ValidationError

logger = logging.getLogger(__name__)

_CODES: list[tuple[type[Exception], str]] = [
    (drf.NotAuthenticated, "not_authenticated"),
    (drf.AuthenticationFailed, "authentication_failed"),
    (drf.PermissionDenied, "permission_denied"),
    (drf.NotFound, "not_found"),
    (drf.MethodNotAllowed, "method_not_allowed"),
    (drf.UnsupportedMediaType, "unsupported_media_type"),
    (drf.ParseError, "parse_error"),
    (drf.ValidationError, "validation_error"),
    (drf.Throttled, "throttled"),
]


def error_body(code: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details or {}}}


def exception_handler(exc: Exception, context: dict[str, Any]) -> Response | None:
    if isinstance(exc, ValidationError):
        return Response(error_body(exc.code, exc.message, {"fields": exc.field_errors}), status=400)
    if isinstance(exc, NotFoundError):
        return Response(error_body(exc.code, exc.message), status=404)
    if isinstance(exc, PortRegistryError):
        status = int(getattr(exc, "http_status", 400))
        return Response(error_body(exc.code, exc.message, exc.details), status=status)
    if isinstance(exc, ObjectDoesNotExist | Http404):
        exc = drf.NotFound()

    response = drf_exception_handler(exc, context)
    if response is None:
        logger.exception("Unhandled API error", exc_info=exc)
        return Response(error_body("internal_error", "Internal server error."), status=500)

    code = next((c for cls, c in _CODES if isinstance(exc, cls)), "error")
    detail = getattr(exc, "detail", None)
    if isinstance(exc, drf.ValidationError):
        fields = detail if isinstance(detail, dict) else {"non_field_errors": detail}
        response.data = error_body(code, "Invalid input.", {"fields": fields})
    else:
        message = str(detail) if detail is not None else str(exc)
        response.data = error_body(code, message)
    return response


def api_not_found(request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
    return JsonResponse(error_body("not_found", f"No API endpoint at {request.path}."), status=404)
