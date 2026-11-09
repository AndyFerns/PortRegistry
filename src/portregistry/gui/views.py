"""Server-rendered GUI pages and HTMX partials.

Views run inside the daemon and use the same services layer as the API; they
never run discovery themselves. All user-controlled values are rendered through
Django's autoescaping templates.
"""

from __future__ import annotations

from typing import Any

from django.contrib import messages
from django.db.models import Count, Q
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods, require_POST

from portregistry.core.application import get_application, has_application
from portregistry.django_app.models import (
    Conflict,
    DiscoveryScan,
    DockerContainer,
    Machine,
    PortReservation,
    ProcessInstance,
    Service,
    Socket,
)
from portregistry.exceptions import NotFoundError, ValidationError
from portregistry.gui.auth import gui_login_required
from portregistry.gui.forms import ReservationForm, ServiceForm, apply_errors
from portregistry.services import queries, registry, reservations
from portregistry.services.conflict_store import active_conflicts
from portregistry.services.history import query_events
from portregistry.services.machines import get_local_machine
from portregistry.services.registry import SUGGESTED_CATEGORIES

PORTS_PAGE = 300
HISTORY_PAGE = 100


def _machine() -> Machine:
    try:
        return get_local_machine()
    except Machine.DoesNotExist as exc:
        raise Http404("The daemon has not initialised the local machine yet.") from exc


def _app() -> Any:
    return get_application() if has_application() else None


def _is_htmx(request: HttpRequest) -> bool:
    """True for htmx partial requests (but not history restores, which need full pages)."""
    return (
        request.headers.get("HX-Request") == "true"
        and request.headers.get("HX-History-Restore-Request") != "true"
    )


def _offset(request: HttpRequest) -> int:
    try:
        return max(0, int(request.GET.get("offset", "0")))
    except ValueError:
        return 0


# ------------------------------------------------------------------ dashboard


def _dashboard_context(machine: Machine) -> dict[str, Any]:
    return {
        "summary": queries.dashboard_summary(machine, _app()),
        "top_conflicts": list(active_conflicts(machine, min_severity="warning")[:8]),
        "recent_events": list(query_events(machine=machine)[:12]),
        "busiest": list(
            ProcessInstance.objects.filter(machine=machine, active=True)
            .annotate(n=Count("sockets", filter=Q(sockets__active=True)))
            .order_by("-n", "name")[:6]
        ),
    }


@gui_login_required
def dashboard(request: HttpRequest) -> HttpResponse:
    machine = _machine()
    return render(
        request, "portregistry/dashboard.html", {"machine": machine, **_dashboard_context(machine)}
    )


@gui_login_required
def dashboard_partial(request: HttpRequest) -> HttpResponse:
    return render(
        request, "portregistry/partials/dashboard_body.html", _dashboard_context(_machine())
    )


@gui_login_required
def status_bar(request: HttpRequest) -> HttpResponse:
    machine = _machine()
    return render(
        request,
        "portregistry/partials/status_bar.html",
        {"fresh": queries.freshness(machine, _app()), "machine": machine},
    )


@gui_login_required
@require_POST
def trigger_scan(request: HttpRequest) -> HttpResponse:
    app = _app()
    if app is None or app.scheduler is None or app.shutting_down:
        return HttpResponse(
            '<span class="badge sev-error">Scheduler not running</span>', status=503
        )
    ticket = app.scheduler.request_native_scan(None, None, "manual")
    note = " (joined pending request)" if ticket.coalesced else ""
    return render(
        request, "portregistry/partials/scan_requested.html", {"ticket": ticket, "note": note}
    )


# ---------------------------------------------------------------------- ports


def _ports_context(request: HttpRequest) -> dict[str, Any]:
    params = request.GET.copy()
    error = None
    try:
        qs = queries.ports_queryset(params)
    except ValidationError as exc:
        error = "; ".join(f"{k}: {', '.join(v)}" for k, v in exc.field_errors.items())
        qs = Socket.objects.none()
    total = qs.count()
    offset = _offset(request)
    rows = list(qs[offset : offset + PORTS_PAGE])
    index = queries.docker_index()
    docker = {s.pk: queries.docker_matches_for(s, index) for s in rows}
    covered = _covered_socket_ids(rows)
    return {
        "rows": rows,
        "docker": docker,
        "covered": covered,
        "total": total,
        "offset": offset,
        "next_offset": offset + PORTS_PAGE if offset + PORTS_PAGE < total else None,
        "prev_offset": max(0, offset - PORTS_PAGE) if offset else None,
        "error": error,
        "params": params,
        "ordering": params.get("ordering", "port"),
    }


def _covered_socket_ids(rows: list[Socket]) -> set[int]:
    ids = {s.pk for s in rows}
    flagged = set(
        Conflict.objects.filter(
            active=True, type="unregistered_listener", socket_id__in=ids
        ).values_list("socket_id", flat=True)
    )
    return ids - flagged


@gui_login_required
def ports(request: HttpRequest) -> HttpResponse:
    template = (
        "portregistry/partials/ports_table.html" if _is_htmx(request) else "portregistry/ports.html"
    )
    return render(request, template, _ports_context(request))


@gui_login_required
def port_detail(request: HttpRequest, pk: int) -> HttpResponse:
    try:
        sock = Socket.objects.select_related("process", "machine", "first_scan", "last_scan").get(
            pk=pk
        )
    except Socket.DoesNotExist as exc:
        raise Http404("Endpoint not found") from exc
    context = {
        "sock": sock,
        "docker": queries.docker_matches_for(sock, queries.docker_index()),
        "covering": queries.reservations_covering(sock),
        "conflicts": Conflict.objects.filter(active=True, socket=sock),
        "history": list(query_events(entity_type="socket", entity_id=str(sock.pk))[:20]),
        "siblings": Socket.objects.filter(machine=sock.machine, port=sock.port, active=True)
        .exclude(pk=sock.pk)
        .select_related("process"),
    }
    return render(request, "portregistry/port_detail.html", context)


@gui_login_required
def process_detail(request: HttpRequest, pk: int) -> HttpResponse:
    try:
        proc = ProcessInstance.objects.select_related("machine").get(pk=pk)
    except ProcessInstance.DoesNotExist as exc:
        raise Http404("Process not found") from exc
    context = {
        "proc": proc,
        "sockets": proc.sockets.order_by("-active", "port"),
        "same_pid": ProcessInstance.objects.filter(machine=proc.machine, pid=proc.pid)
        .exclude(pk=proc.pk)
        .order_by("-first_seen"),
        "history": list(query_events(entity_type="process", entity_id=str(proc.pk))[:20]),
    }
    return render(request, "portregistry/process_detail.html", context)


# ------------------------------------------------------------------- services


@gui_login_required
def services(request: HttpRequest) -> HttpResponse:
    q = request.GET.get("q", "").strip()
    return render(
        request,
        "portregistry/services.html",
        {"services": registry.list_services(_machine(), search=q or None), "q": q},
    )


@gui_login_required
@require_http_methods(["GET", "POST"])
def service_create(request: HttpRequest) -> HttpResponse:
    form = ServiceForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            service = registry.create_service(_machine(), form.cleaned_data)
        except ValidationError as exc:
            apply_errors(form, exc)
        else:
            messages.success(request, f"Service '{service.name}' registered.")
            return redirect("gui-service", pk=service.pk)
    return render(
        request,
        "portregistry/service_form.html",
        {"form": form, "categories": SUGGESTED_CATEGORIES, "title": "Register service"},
    )


def _get_service(pk: int) -> Service:
    try:
        return registry.get_service(pk)
    except NotFoundError as exc:
        raise Http404(str(exc)) from exc


@gui_login_required
def service_detail(request: HttpRequest, pk: int) -> HttpResponse:
    service = _get_service(pk)
    res = list(reservations.list_reservations(service_id=service.pk, status="all"))
    return render(
        request,
        "portregistry/service_detail.html",
        {
            "service": service,
            "reservations": res,
            "conflicts": list(active_conflicts(service_id=service.pk)),
            "history": list(query_events(entity_type="service", entity_id=str(service.pk))[:20]),
        },
    )


@gui_login_required
@require_http_methods(["GET", "POST"])
def service_edit(request: HttpRequest, pk: int) -> HttpResponse:
    service = _get_service(pk)
    initial = {f: getattr(service, f) for f in ServiceForm.base_fields}
    form = ServiceForm(request.POST or None, initial=initial)
    if request.method == "POST" and form.is_valid():
        try:
            registry.update_service(service, form.cleaned_data, partial=False)
        except ValidationError as exc:
            apply_errors(form, exc)
        else:
            messages.success(request, f"Service '{service.name}' updated.")
            return redirect("gui-service", pk=service.pk)
    return render(
        request,
        "portregistry/service_form.html",
        {
            "form": form,
            "service": service,
            "categories": SUGGESTED_CATEGORIES,
            "title": f"Edit {service.name}",
        },
    )


@gui_login_required
@require_http_methods(["GET", "POST"])
def service_delete(request: HttpRequest, pk: int) -> HttpResponse:
    service = _get_service(pk)
    if request.method == "POST":
        result = registry.delete_service(service)
        kept = result["unlinked_reservations"]
        messages.success(
            request,
            f"Service '{result['deleted']['name']}' deleted."
            + (f" {len(kept)} reservation(s) kept but unlinked." if kept else ""),
        )
        return redirect("gui-services")
    return render(
        request,
        "portregistry/confirm.html",
        {
            "title": f"Delete service '{service.name}'?",
            "body": "Its reservations are kept (unlinked from the service) and history is preserved.",
            "danger": True,
            "cancel_url": f"/services/{service.pk}/",
            "affected": [str(r) for r in service.reservations.all()],
        },
    )


# --------------------------------------------------------------- reservations


@gui_login_required
def reservations_list(request: HttpRequest) -> HttpResponse:
    status = request.GET.get("status", "active")
    if status not in ("active", "released", "all"):
        status = "active"
    machine = _machine()
    rows = list(reservations.list_reservations(machine, status=status))
    conflict_map: dict[int, list[Conflict]] = {}
    for c in Conflict.objects.filter(active=True).filter(
        Q(reservation__in=rows) | Q(related_reservation__in=rows)
    ):
        for rid in {c.reservation_id, c.related_reservation_id} - {None}:
            conflict_map.setdefault(rid, []).append(c)
    attention = {
        r.pk
        for r in rows
        if r.status == "active" and any(c.severity != "info" for c in conflict_map.get(r.pk, []))
    }
    return render(
        request,
        "portregistry/reservations.html",
        {"rows": rows, "status": status, "conflict_map": conflict_map, "attention": attention},
    )


def _get_reservation(pk: int) -> PortReservation:
    try:
        return reservations.get_reservation(pk)
    except NotFoundError as exc:
        raise Http404(str(exc)) from exc


@gui_login_required
@require_http_methods(["GET", "POST"])
def reservation_create(request: HttpRequest) -> HttpResponse:
    machine = _machine()
    initial: dict[str, Any] = {
        "port": request.GET.get("port"),
        "protocol": request.GET.get("protocol", "tcp"),
        "bind_address": "*",
    }
    service_ref = request.GET.get("service", "")
    if service_ref.isdigit():
        initial["service"] = Service.objects.filter(pk=int(service_ref), machine=machine).first()
    form = ReservationForm(request.POST or None, machine=machine, initial=initial)
    if request.method == "POST" and form.is_valid():
        try:
            res, conflicts = reservations.create_reservation(machine, form.to_payload())
        except ValidationError as exc:
            apply_errors(form, exc)
        else:
            serious = [c for c in conflicts if c.severity != "info"]
            if serious:
                messages.warning(
                    request,
                    f"Reservation #{res.pk} created with {len(serious)} conflict(s); see below.",
                )
            else:
                messages.success(request, f"Reservation #{res.pk} created. No conflicts detected.")
            return redirect("gui-reservation-edit", pk=res.pk)
    return render(
        request, "portregistry/reservation_form.html", {"form": form, "title": "New reservation"}
    )


@gui_login_required
@require_http_methods(["GET", "POST"])
def reservation_edit(request: HttpRequest, pk: int) -> HttpResponse:
    res = _get_reservation(pk)
    machine = res.machine
    initial = {
        "port": res.port,
        "protocol": res.protocol,
        "bind_address": res.bind_address,
        "service": res.service,
        "description": res.description,
    }
    form = ReservationForm(request.POST or None, machine=machine, initial=initial)
    if request.method == "POST" and form.is_valid():
        try:
            reservations.update_reservation(res, form.to_payload(), partial=True)
        except ValidationError as exc:
            apply_errors(form, exc)
        else:
            messages.success(request, f"Reservation #{res.pk} updated.")
            return redirect("gui-reservation-edit", pk=res.pk)
    return render(
        request,
        "portregistry/reservation_form.html",
        {
            "form": form,
            "reservation": res,
            "conflicts": reservations.conflicts_for(res),
            "history": list(query_events(entity_type="reservation", entity_id=str(res.pk))[:20]),
            "title": f"Reservation #{res.pk}",
        },
    )


@gui_login_required
@require_POST
def reservation_release(request: HttpRequest, pk: int) -> HttpResponse:
    res = reservations.release_reservation(_get_reservation(pk))
    messages.success(request, f"Reservation #{res.pk} released.")
    return redirect("gui-reservations")


@gui_login_required
@require_POST
def reservation_reactivate(request: HttpRequest, pk: int) -> HttpResponse:
    res, _ = reservations.update_reservation(_get_reservation(pk), {"status": "active"})
    messages.success(request, f"Reservation #{res.pk} is active again.")
    return redirect("gui-reservation-edit", pk=res.pk)


@gui_login_required
@require_http_methods(["GET", "POST"])
def reservation_delete(request: HttpRequest, pk: int) -> HttpResponse:
    res = _get_reservation(pk)
    if request.method == "POST":
        reservations.delete_reservation(res)
        messages.success(request, f"Reservation #{pk} deleted (a history snapshot was kept).")
        return redirect("gui-reservations")
    return render(
        request,
        "portregistry/confirm.html",
        {
            "title": f"Permanently delete reservation #{res.pk} ({res})?",
            "body": "Prefer Release to keep the record. Deletion keeps a snapshot in history.",
            "danger": True,
            "cancel_url": f"/reservations/{res.pk}/",
        },
    )


@gui_login_required
@require_POST
def reservation_check(request: HttpRequest) -> HttpResponse:
    """HTMX partial: live occupancy/overlap check while filling the form."""
    machine = _machine()
    form = ReservationForm(request.POST, machine=machine)
    findings: list[Any] = []
    error = None
    if form.is_valid():
        exclude = request.POST.get("exclude_id")
        try:
            findings = reservations.check_reservation(
                machine,
                {k: v for k, v in form.to_payload().items() if k != "description"},
                exclude_id=int(exclude) if exclude and exclude.isdigit() else None,
            )
        except ValidationError as exc:
            error = (
                exc.message
                + " "
                + "; ".join(f"{k}: {', '.join(v)}" for k, v in exc.field_errors.items())
            )
    else:
        error = "Enter a valid port and address to check availability."
    return render(
        request,
        "portregistry/partials/reservation_check.html",
        {"findings": findings, "error": error},
    )


# ------------------------------------------------------------------ conflicts


@gui_login_required
def conflicts(request: HttpRequest) -> HttpResponse:
    show_info = request.GET.get("info") == "1"
    machine = _machine()
    qs = active_conflicts(machine, min_severity=None if show_info else "warning")
    rank = {"error": 0, "warning": 1, "info": 2}
    rows = sorted(qs, key=lambda c: (rank.get(c.severity, 9), c.type, c.port or 0))
    info_count = active_conflicts(machine, severity="info").count()
    template = (
        "portregistry/partials/conflicts_list.html"
        if _is_htmx(request)
        else "portregistry/conflicts.html"
    )
    return render(
        request, template, {"rows": rows, "show_info": show_info, "info_count": info_count}
    )


# -------------------------------------------------------------------- history


@gui_login_required
def history(request: HttpRequest) -> HttpResponse:
    type_prefix = request.GET.get("type", "").strip()
    q = request.GET.get("q", "").strip()
    severity = request.GET.get("severity", "").strip()
    qs = query_events(type_prefix=type_prefix or None, search=q or None, severity=severity or None)
    offset = _offset(request)
    total = qs.count()
    rows = list(qs[offset : offset + HISTORY_PAGE])
    context = {
        "rows": rows,
        "total": total,
        "offset": offset,
        "next_offset": offset + HISTORY_PAGE if offset + HISTORY_PAGE < total else None,
        "prev_offset": max(0, offset - HISTORY_PAGE) if offset else None,
        "type": type_prefix,
        "q": q,
        "severity": severity,
        "type_choices": [
            "endpoint",
            "process",
            "service",
            "reservation",
            "conflict",
            "container",
            "docker",
            "scan",
            "discovery",
            "machine",
        ],
    }
    template = (
        "portregistry/partials/history_table.html"
        if _is_htmx(request)
        else "portregistry/history.html"
    )
    return render(request, template, context)


@gui_login_required
def recent_events(request: HttpRequest) -> HttpResponse:
    return render(
        request,
        "portregistry/partials/recent_events.html",
        {"recent_events": list(query_events(machine=_machine())[:12])},
    )


# ----------------------------------------------------------- containers & machine


@gui_login_required
def containers(request: HttpRequest) -> HttpResponse:
    show_removed = request.GET.get("removed") == "1"
    qs = DockerContainer.objects.select_related("image").prefetch_related("port_mappings")
    if not show_removed:
        qs = qs.filter(present=True)
    return render(
        request,
        "portregistry/containers.html",
        {"rows": qs.order_by("name"), "show_removed": show_removed},
    )


@gui_login_required
def machine_view(request: HttpRequest) -> HttpResponse:
    machine = _machine()
    app = _app()
    return render(
        request,
        "portregistry/machine.html",
        {
            "machine": machine,
            "status": queries.status_payload(app, machine) if app else None,
            "scans": DiscoveryScan.objects.filter(machine=machine).order_by("-started_at")[:15],
            "config": app.config.as_public_dict() if app else None,
        },
    )
