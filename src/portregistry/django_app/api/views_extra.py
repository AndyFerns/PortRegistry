"""API views for v0.2 usability features (ignore rules, adopt, free ports,
timeline, diagnostics, token rotation, manifests, alerts, saved filters,
onboarding, autostart status)."""

from __future__ import annotations

from typing import Any

from django.contrib.sessions.models import Session
from rest_framework.authentication import SessionAuthentication
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from portregistry.config import rotate_token
from portregistry.core.application import get_application
from portregistry.django_app.api import serializers as ser
from portregistry.django_app.api.views import body, local_machine, paginate
from portregistry.django_app.models import ProcessInstance, Socket
from portregistry.exceptions import NotFoundError, ValidationError
from portregistry.services import (
    adopt,
    diagnostics,
    free_ports,
    ignore_rules,
    manifest,
    preferences,
    process_control,
    timeline,
)
from portregistry.services.db import write_transaction
from portregistry.services.history import EventSpec, record_events


def _socket(pk: int) -> Socket:
    try:
        return Socket.objects.select_related("process", "machine").get(pk=pk)
    except Socket.DoesNotExist as exc:
        raise NotFoundError(f"Endpoint {pk} not found.") from exc


def _process(pk: int) -> ProcessInstance:
    try:
        return ProcessInstance.objects.select_related("machine").get(pk=pk)
    except ProcessInstance.DoesNotExist as exc:
        raise NotFoundError(f"Process {pk} not found.") from exc


def _int(value: Any, name: str) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError("Invalid parameter.", {name: ["Must be an integer."]}) from exc


# ---------------------------------------------------------------- ignore rules


class IgnoreRuleListView(APIView):
    def get(self, request: Request) -> Response:
        return paginate(
            self, request, ignore_rules.list_rules(local_machine()), ser.ignore_rule_dict
        )

    def post(self, request: Request) -> Response:
        rule = ignore_rules.create_rule(local_machine(), body(request))
        return Response(ser.ignore_rule_dict(rule), status=201)


class IgnoreRuleDetailView(APIView):
    def get(self, request: Request, pk: int) -> Response:
        return Response(ser.ignore_rule_dict(ignore_rules.get_rule(pk)))

    def patch(self, request: Request, pk: int) -> Response:
        rule = ignore_rules.update_rule(ignore_rules.get_rule(pk), body(request))
        return Response(ser.ignore_rule_dict(rule))

    def delete(self, request: Request, pk: int) -> Response:
        return Response({"deleted": ignore_rules.delete_rule(ignore_rules.get_rule(pk))})


class PortKnownView(APIView):
    """Mark an endpoint as known (creates an ignore rule for it)."""

    def post(self, request: Request, pk: int) -> Response:
        rule = ignore_rules.mark_socket_known(_socket(pk))
        return Response(ser.ignore_rule_dict(rule), status=201)


class ProcessKnownView(APIView):
    def post(self, request: Request, pk: int) -> Response:
        rule = ignore_rules.mark_process_known(_process(pk))
        return Response(ser.ignore_rule_dict(rule), status=201)


# ----------------------------------------------------------------------- adopt


class AdoptView(APIView):
    def get(self, request: Request) -> Response:
        return Response(
            adopt.propose(
                socket_id=_int(request.query_params.get("socket"), "socket"),
                process_id=_int(request.query_params.get("process"), "process"),
            )
        )

    def post(self, request: Request) -> Response:
        result = adopt.apply(local_machine(), body(request))
        return Response(
            {
                "service": ser.service_dict(result["service"]),
                "reservations": [ser.reservation_dict(r) for r in result["reservations"]],
            },
            status=201,
        )


# --------------------------------------------------------- free ports, timeline


class FreePortsView(APIView):
    def get(self, request: Request) -> Response:
        query = free_ports.parse_query(dict(request.query_params.items()))
        return Response(free_ports.find_free_ports(local_machine(), query))


class TimelineView(APIView):
    def get(self, request: Request) -> Response:
        port, protocol, days = timeline.parse_params(dict(request.query_params.items()))
        return Response(timeline.build_timeline(local_machine(), port, protocol, days))


# ---------------------------------------------------------- doctor & security


class DiagnosticsView(APIView):
    def get(self, request: Request) -> Response:
        return Response(diagnostics.run_diagnostics(local_machine()))

    def post(self, request: Request) -> Response:
        """Run diagnostics and remember that a health check was done (onboarding)."""
        result = diagnostics.run_diagnostics(local_machine())
        preferences.set_setting("doctor_ran", True)
        return Response(result)


class TokenRotateView(APIView):
    """Replace the local API token. The new token is written to the token file
    only; it is never returned or logged. Browser sessions are revoked unless
    ``keep_sessions`` is true."""

    def post(self, request: Request) -> Response:
        data = body(request)
        keep_sessions = bool(data.get("keep_sessions", False))
        app = get_application()
        app.token = rotate_token(app.config.paths)
        revoked = 0
        with write_transaction():
            if not keep_sessions:
                revoked = Session.objects.all().delete()[0]
            record_events(
                local_machine(),
                [
                    EventSpec(
                        "security.token_rotated",
                        "Local API token rotated"
                        + (f"; {revoked} browser session(s) revoked" if revoked else ""),
                        severity="warning",
                        entity_type="security",
                        entity_id="token",
                    )
                ],
            )
        return Response(
            {
                "rotated": True,
                "sessions_revoked": revoked,
                "token_file": str(app.config.paths.token_file),
            }
        )


# -------------------------------------------------------------------- manifest


class ManifestApplyView(APIView):
    def post(self, request: Request) -> Response:
        data = body(request)
        return Response(
            manifest.apply_manifest(
                local_machine(),
                data.get("document"),
                str(data.get("source") or ""),
                prune=bool(data.get("prune", False)),
                dry_run=bool(data.get("dry_run", False)),
            )
        )


class ManifestExportView(APIView):
    def get(self, request: Request) -> Response:
        params = request.query_params
        return Response(
            manifest.export_registry(
                local_machine(),
                service=params.get("service") or None,
                include_released=params.get("include_released") in ("1", "true"),
            )
        )


# ---------------------------------------------------------------------- alerts


class AlertsView(APIView):
    def get(self, request: Request) -> Response:
        dispatcher = get_application().alerts
        return Response(dispatcher.describe() if dispatcher else {"webhooks": []})


class AlertsTestView(APIView):
    def post(self, request: Request) -> Response:
        dispatcher = get_application().alerts
        if dispatcher is None or not dispatcher.enabled:
            raise ValidationError(
                "No webhooks configured.",
                {
                    "webhooks": [
                        "Add [[alerts.webhook]] entries to config.toml and restart the daemon."
                    ]
                },
            )
        return Response({"results": dispatcher.send_test()})


# --------------------------------------------------------------- saved filters


class SavedFilterListView(APIView):
    def get(self, request: Request) -> Response:
        page = request.query_params.get("page") or None
        return paginate(
            self, request, preferences.list_filters(local_machine(), page), ser.saved_filter_dict
        )

    def post(self, request: Request) -> Response:
        saved = preferences.create_filter(local_machine(), body(request))
        return Response(ser.saved_filter_dict(saved), status=201)


class SavedFilterDetailView(APIView):
    def get(self, request: Request, ref: str) -> Response:
        return Response(
            ser.saved_filter_dict(
                preferences.get_filter(local_machine(), ref, request.query_params.get("page"))
            )
        )

    def delete(self, request: Request, ref: str) -> Response:
        saved = preferences.get_filter(local_machine(), ref, request.query_params.get("page"))
        data = ser.saved_filter_dict(saved)
        preferences.delete_filter(saved)
        return Response({"deleted": data})


# ---------------------------------------------------- onboarding and autostart


def _autostart_installed() -> bool | None:
    from portregistry.daemon import autostart

    return autostart.status().installed


class OnboardingView(APIView):
    def get(self, request: Request) -> Response:
        return Response(
            preferences.onboarding_state(
                local_machine(), autostart_installed=_autostart_installed()
            )
        )


class OnboardingDismissView(APIView):
    def post(self, request: Request) -> Response:
        dismissed = bool(body(request).get("dismissed", True))
        preferences.set_setting("onboarding_dismissed", dismissed)
        return Response({"dismissed": dismissed})


class AutostartStatusView(APIView):
    def get(self, request: Request) -> Response:
        from portregistry.daemon import autostart

        return Response(autostart.status().as_dict())


# ------------------------------------------------------------- process control


def _flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _actor(request: Request) -> str:
    """Who asked: browser sessions are always "gui"; token clients name themselves."""
    if isinstance(getattr(request, "successful_authenticator", None), SessionAuthentication):
        return "gui"
    value = request.headers.get("X-PortRegistry-Client", "").strip().lower()
    return value if value in ("cli", "tui") else "api"


def _ancestors(request: Request) -> tuple[int, ...]:
    return process_control.parse_ancestors(request.headers.get("X-PortRegistry-Client-Ancestors"))


class ControlStatusView(APIView):
    def get(self, request: Request) -> Response:
        return Response(process_control.control_state())


class ProcessStopPreviewView(APIView):
    """Assessment + copy-and-run commands. Never issues a code; works when control is off."""

    def get(self, request: Request, pk: int) -> Response:
        params = request.query_params
        return Response(
            process_control.preview(
                pk,
                mode=params.get("mode") or "process",
                force=_flag(params.get("force")),
                client_ancestors=_ancestors(request),
            )
        )


class ProcessStopRequestView(APIView):
    """Step 1 of 2: returns a single-use code valid for 30 seconds."""

    def post(self, request: Request, pk: int) -> Response:
        data = body(request)
        return Response(
            process_control.request_stop(
                pk,
                mode=str(data.get("mode") or "process"),
                force=_flag(data.get("force")),
                actor=_actor(request),
                client_ancestors=_ancestors(request),
            ),
            status=201,
        )


class ProcessStopConfirmView(APIView):
    """Step 2 of 2: ``{"code": ..., "pid": <typed PID>}``."""

    def post(self, request: Request) -> Response:
        data = body(request)
        operation = process_control.confirm_stop(
            str(data.get("code") or ""),
            pid=data.get("pid"),
            actor=_actor(request),
            client_ancestors=_ancestors(request),
        )
        return Response(operation, status=200 if operation["state"] == "done" else 202)


class ProcessStopOperationView(APIView):
    def get(self, request: Request, op_id: str) -> Response:
        return Response(process_control.get_operation(op_id))
