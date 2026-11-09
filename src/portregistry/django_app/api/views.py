"""HTTP/JSON API views. Thin: validation and logic live in ``portregistry.services``."""

from __future__ import annotations

import threading
from collections import defaultdict
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any

from django.db.models import Q, QuerySet
from django.utils.dateparse import parse_datetime
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from portregistry import __version__
from portregistry.core.application import get_application, has_application
from portregistry.django_app.api import serializers as ser
from portregistry.django_app.api.pagination import Pagination
from portregistry.django_app.models import (
    Conflict,
    DiscoveryScan,
    DockerContainer,
    Machine,
    ProcessInstance,
    Socket,
)
from portregistry.exceptions import NotFoundError, ValidationError
from portregistry.services import queries, registry, reservations
from portregistry.services.conflict_store import active_conflicts
from portregistry.services.history import query_events
from portregistry.services.machines import get_local_machine
from portregistry.services.validation import Errors, clean_port, clean_protocol


def local_machine() -> Machine:
    try:
        return get_local_machine()
    except Machine.DoesNotExist as exc:
        raise NotFoundError("Local machine is not initialised yet.") from exc


def paginate(
    view: APIView, request: Request, items: QuerySet[Any] | list[Any], fn: Callable[[Any], Any]
) -> Response:
    paginator = Pagination()
    page = paginator.paginate_queryset(items, request, view=view)
    return paginator.get_paginated_response([fn(x) for x in (page or [])])


def body(request: Request) -> dict[str, Any]:
    data = request.data
    if not isinstance(data, dict):
        raise ValidationError(
            "Expected a JSON object.", {"non_field_errors": ["Expected an object."]}
        )
    return dict(data)


def int_param(request: Request, name: str) -> int | None:
    value = request.query_params.get(name)
    if value in (None, ""):
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise ValidationError("Invalid filter.", {name: ["Must be an integer."]}) from exc


def reservation_conflict_map(ids: Iterable[int]) -> dict[int, list[Conflict]]:
    ids = list(ids)
    result: dict[int, list[Conflict]] = defaultdict(list)
    if not ids:
        return result
    for c in Conflict.objects.filter(active=True).filter(
        Q(reservation_id__in=ids) | Q(related_reservation_id__in=ids)
    ):
        if c.reservation_id in ids:
            result[c.reservation_id].append(c)
        if c.related_reservation_id in ids and c.related_reservation_id != c.reservation_id:
            result[c.related_reservation_id].append(c)
    return result


# ---------------------------------------------------------------- daemon


class HealthView(APIView):
    """Liveness/readiness. Unauthenticated; exposes no sensitive information."""

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]

    def get(self, request: Request) -> Response:
        status = "ok"
        if has_application() and get_application().shutting_down:
            status = "stopping"
        return Response(
            {"status": status, "service": "portregistry", "version": __version__, "api": "v1"}
        )


class StatusView(APIView):
    def get(self, request: Request) -> Response:
        return Response(queries.status_payload(get_application(), local_machine()))


class ShutdownView(APIView):
    def post(self, request: Request) -> Response:
        app = get_application()
        # Respond first, then stop the server.
        threading.Timer(0.3, app.request_shutdown).start()
        return Response({"status": "shutting_down"}, status=202)


class GuiLinkView(APIView):
    """Issue a single-use, short-lived browser login link (for ``portregistry gui``)."""

    def post(self, request: Request) -> Response:
        app = get_application()
        nonce = app.links.issue()
        return Response(
            {"url": f"{app.config.base_url}/login/link/{nonce}/", "expires_in": int(app.links.ttl)}
        )


# --------------------------------------------------------------- machines


class MachineListView(APIView):
    def get(self, request: Request) -> Response:
        return paginate(self, request, Machine.objects.order_by("hostname"), ser.machine_dict)


class MachineDetailView(APIView):
    def get(self, request: Request, machine_uuid: str) -> Response:
        machine = queries.resolve_machine(machine_uuid)
        if machine is None:
            raise NotFoundError(f"Machine '{machine_uuid}' not found.")
        return Response(ser.machine_dict(machine))


# ------------------------------------------------------------ observations


class PortListView(APIView):
    def get(self, request: Request) -> Response:
        qs = queries.ports_queryset(request.query_params)
        index = queries.docker_index()
        ignored = queries.IgnoreClassifier()
        return paginate(
            self,
            request,
            qs,
            lambda s: ser.socket_dict(
                s, docker=queries.docker_matches_for(s, index), ignored=ignored.reason(s)
            ),
        )


class PortDetailView(APIView):
    def get(self, request: Request, pk: int) -> Response:
        try:
            sock = Socket.objects.select_related("process", "machine").get(pk=pk)
        except Socket.DoesNotExist as exc:
            raise NotFoundError(f"Endpoint {pk} not found.") from exc
        data = ser.socket_dict(
            sock, docker=queries.docker_matches_for(sock, queries.docker_index())
        )
        if sock.process is not None:
            data["process"] = ser.process_dict(sock.process)
        data["reservations"] = [
            ser.reservation_dict(r) for r in queries.reservations_covering(sock)
        ]
        data["conflicts"] = [
            ser.conflict_dict(c) for c in Conflict.objects.filter(active=True, socket=sock)
        ]
        return Response(data)


class ProcessListView(APIView):
    def get(self, request: Request) -> Response:
        return paginate(
            self, request, queries.processes_queryset(request.query_params), ser.process_dict
        )


class ProcessDetailView(APIView):
    def get(self, request: Request, pk: int) -> Response:
        try:
            proc = ProcessInstance.objects.select_related("machine").get(pk=pk)
        except ProcessInstance.DoesNotExist as exc:
            raise NotFoundError(f"Process {pk} not found.") from exc
        sockets = list(proc.sockets.order_by("-active", "port"))
        return Response(ser.process_dict(proc, sockets=sockets))


class ContainerListView(APIView):
    def get(self, request: Request) -> Response:
        qs = DockerContainer.objects.select_related("image").prefetch_related("port_mappings")
        present = request.query_params.get("present", "true").lower()
        if present in ("true", "1"):
            qs = qs.filter(present=True)
        elif present in ("false", "0"):
            qs = qs.filter(present=False)
        app = get_application() if has_application() else None
        response = paginate(self, request, qs.order_by("name"), ser.container_dict)
        response.data["docker"] = app.docker_provider.as_dict() if app else None
        return response


class ContainerDetailView(APIView):
    def get(self, request: Request, ref: str) -> Response:
        qs = DockerContainer.objects.select_related("image")
        container = None
        if ref.isdigit():
            container = qs.filter(pk=int(ref)).first()
        if container is None:
            container = qs.filter(Q(container_id__startswith=ref) | Q(name=ref)).first()
        if container is None:
            raise NotFoundError(f"Container '{ref}' not found.")
        return Response(ser.container_dict(container))


# ---------------------------------------------------------------- services


class ServiceListView(APIView):
    def get(self, request: Request) -> Response:
        qs = registry.list_services(search=request.query_params.get("q"))
        return paginate(self, request, qs, ser.service_dict)

    def post(self, request: Request) -> Response:
        service = registry.create_service(local_machine(), body(request))
        return Response(ser.service_dict(service), status=201)


class ServiceDetailView(APIView):
    def get(self, request: Request, ref: str) -> Response:
        service = registry.get_service(ref)
        data = ser.service_dict(service)
        res = list(reservations.list_reservations(service_id=service.pk, status="all"))
        cmap = reservation_conflict_map(r.pk for r in res)
        data["reservations"] = [ser.reservation_dict(r, cmap.get(r.pk, [])) for r in res]
        data["conflicts"] = [ser.conflict_dict(c) for c in active_conflicts(service_id=service.pk)]
        return Response(data)

    def put(self, request: Request, ref: str) -> Response:
        service = registry.update_service(registry.get_service(ref), body(request), partial=False)
        return Response(ser.service_dict(service))

    def patch(self, request: Request, ref: str) -> Response:
        service = registry.update_service(registry.get_service(ref), body(request), partial=True)
        return Response(ser.service_dict(service))

    def delete(self, request: Request, ref: str) -> Response:
        return Response(registry.delete_service(registry.get_service(ref)))


# ------------------------------------------------------------ reservations


class ReservationListView(APIView):
    def get(self, request: Request) -> Response:
        params = request.query_params
        errors = Errors()
        protocol = clean_protocol(params["protocol"], errors) if params.get("protocol") else None
        status = params.get("status", "active")
        if status not in ("active", "released", "all"):
            errors.add("status", "Status must be active, released or all.")
        errors.raise_if_any("Invalid filter.")
        service_id = None
        if params.get("service"):
            service_id = registry.get_service(params["service"]).pk
        qs = reservations.list_reservations(
            status=status, protocol=protocol, port=int_param(request, "port"), service_id=service_id
        )
        paginator = Pagination()
        page = paginator.paginate_queryset(qs, request, view=self) or []
        cmap = reservation_conflict_map(r.pk for r in page)
        return paginator.get_paginated_response(
            [ser.reservation_dict(r, cmap.get(r.pk, [])) for r in page]
        )

    def post(self, request: Request) -> Response:
        res, conflicts = reservations.create_reservation(local_machine(), body(request))
        return Response(ser.reservation_dict(res, conflicts), status=201)


class ReservationDetailView(APIView):
    def get(self, request: Request, pk: int) -> Response:
        res = reservations.get_reservation(pk)
        return Response(ser.reservation_dict(res, reservations.conflicts_for(res)))

    def put(self, request: Request, pk: int) -> Response:
        res, conflicts = reservations.update_reservation(
            reservations.get_reservation(pk), body(request), partial=False
        )
        return Response(ser.reservation_dict(res, conflicts))

    def patch(self, request: Request, pk: int) -> Response:
        res, conflicts = reservations.update_reservation(
            reservations.get_reservation(pk), body(request), partial=True
        )
        return Response(ser.reservation_dict(res, conflicts))

    def delete(self, request: Request, pk: int) -> Response:
        snapshot = reservations.delete_reservation(reservations.get_reservation(pk))
        return Response({"deleted": snapshot})


class ReservationReleaseView(APIView):
    def post(self, request: Request, pk: int) -> Response:
        res = reservations.release_reservation(reservations.get_reservation(pk))
        return Response(ser.reservation_dict(res, reservations.conflicts_for(res)))


class ReservationCheckView(APIView):
    """Dry run: report occupancy and overlaps for a prospective reservation."""

    def post(self, request: Request) -> Response:
        data = body(request)
        exclude = data.pop("exclude_id", None)
        exclude_id = (
            int(exclude) if isinstance(exclude, int | str) and str(exclude).isdigit() else None
        )
        findings = reservations.check_reservation(local_machine(), data, exclude_id=exclude_id)
        return Response(
            {
                "advisory": True,
                "conflict_free": not any(f.severity != "info" for f in findings),
                "findings": [ser.finding_dict(f) for f in findings],
            }
        )


# ---------------------------------------------------------------- conflicts


class ConflictListView(APIView):
    def get(self, request: Request) -> Response:
        params = request.query_params
        state = params.get("state", "active")
        if state == "active":
            qs = active_conflicts(
                type_=params.get("type") or None,
                severity=params.get("severity") or None,
                min_severity=params.get("min_severity") or None,
                certainty=params.get("certainty") or None,
                reservation_id=int_param(request, "reservation"),
                service_id=int_param(request, "service"),
            )
        elif state in ("resolved", "all"):
            qs = Conflict.objects.all() if state == "all" else Conflict.objects.filter(active=False)
            if params.get("type"):
                qs = qs.filter(type=params["type"])
        else:
            raise ValidationError(
                "Invalid filter.", {"state": ["Must be active, resolved or all."]}
            )
        severity_rank = {"error": 0, "warning": 1, "info": 2}
        items = sorted(
            qs,
            key=lambda c: (severity_rank.get(c.severity, 9), c.type, c.port or 0, c.pk),
        )
        return paginate(self, request, items, ser.conflict_dict)


# ---------------------------------------------------------------- discovery


class ScanRequestView(APIView):
    def post(self, request: Request) -> Response:
        data = body(request)
        errors = Errors()
        protocol = clean_protocol(data["protocol"], errors) if data.get("protocol") else None
        port = clean_port(data["port"], errors) if data.get("port") not in (None, "") else None
        errors.raise_if_any("Invalid scan request.")
        app = get_application()
        if app.scheduler is None or app.shutting_down:
            return Response(
                {
                    "error": {
                        "code": "unavailable",
                        "message": "Scheduler is not running.",
                        "details": {},
                    }
                },
                status=503,
            )
        ticket = app.scheduler.request_native_scan(protocol, port, "manual")
        payload = ticket.as_dict()
        payload["coalesced"] = ticket.coalesced > 0
        return Response(payload, status=202)


class ScanTicketView(APIView):
    def get(self, request: Request, ticket_id: int) -> Response:
        app = get_application()
        ticket = app.scheduler.get_ticket(ticket_id) if app.scheduler else None
        if ticket is None:
            raise NotFoundError(f"Scan request {ticket_id} not found (tickets are kept in memory).")
        payload = ticket.as_dict()
        if ticket.scan_id:
            scan = DiscoveryScan.objects.filter(pk=ticket.scan_id).first()
            payload["scan"] = ser.scan_dict(scan) if scan else None
        return Response(payload)


class ScanListView(APIView):
    def get(self, request: Request) -> Response:
        qs = DiscoveryScan.objects.all().order_by("-started_at", "-id")
        if request.query_params.get("kind"):
            qs = qs.filter(kind=request.query_params["kind"])
        if request.query_params.get("status"):
            qs = qs.filter(status=request.query_params["status"])
        return paginate(self, request, qs, ser.scan_dict)


class ScanDetailView(APIView):
    def get(self, request: Request, pk: int) -> Response:
        try:
            return Response(ser.scan_dict(DiscoveryScan.objects.get(pk=pk)))
        except DiscoveryScan.DoesNotExist as exc:
            raise NotFoundError(f"Scan {pk} not found.") from exc


# ------------------------------------------------------------------ history


class HistoryView(APIView):
    def get(self, request: Request) -> Response:
        params = request.query_params
        since: datetime | None = None
        if params.get("since"):
            since = parse_datetime(params["since"])
            if since is None:
                raise ValidationError("Invalid filter.", {"since": ["Use an ISO 8601 timestamp."]})
        qs = query_events(
            type_prefix=params.get("type") or None,
            entity_type=params.get("entity_type") or None,
            entity_id=params.get("entity_id") or None,
            severity=params.get("severity") or None,
            since=since,
            search=params.get("q") or None,
            include_noise=params.get("noise") in ("1", "true", "all"),
        ).select_related("machine")
        response = paginate(self, request, qs, ser.event_dict)
        if params.get("noise") not in ("1", "true", "all"):
            response.data["hidden_noise"] = (
                query_events(
                    type_prefix=params.get("type") or None,
                    since=since,
                    search=params.get("q") or None,
                    include_noise=True,
                )
                .filter(noise=True)
                .count()
            )
        return response
