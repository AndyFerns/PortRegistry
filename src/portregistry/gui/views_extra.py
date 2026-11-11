"""GUI views for v0.2 features: adopt, mark-as-known, ignore rules, timeline,
free-port suggestion, onboarding and saved filters."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from django.contrib import messages
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_http_methods, require_POST

from portregistry.django_app.models import IgnoreRule, ProcessInstance, Socket
from portregistry.exceptions import NotFoundError, ValidationError
from portregistry.gui.auth import gui_login_required
from portregistry.gui.forms import ReservationForm
from portregistry.gui.views import _machine
from portregistry.services import (
    adopt,
    free_ports,
    ignore_rules,
    preferences,
    process_control,
    reservations,
    timeline,
)
from portregistry.services.registry import SUGGESTED_CATEGORIES


def _back(request: HttpRequest, default: str) -> str:
    target = request.POST.get("next") or request.META.get("HTTP_REFERER") or default
    if url_has_allowed_host_and_scheme(
        target, allowed_hosts={request.get_host()}, require_https=False
    ):
        return target
    return default


def _errors_text(exc: ValidationError) -> str:
    parts = [f"{k}: {'; '.join(v)}" for k, v in exc.field_errors.items()]
    return exc.message + (" " + " | ".join(parts) if parts else "")


# ------------------------------------------------------------------ adopt


@gui_login_required
@require_http_methods(["GET", "POST"])
def adopt_view(request: HttpRequest) -> HttpResponse:
    machine = _machine()
    source = request.POST if request.method == "POST" else request.GET
    socket_id = source.get("socket") or None
    process_id = source.get("process") or None
    try:
        proposal = adopt.propose(
            socket_id=int(socket_id) if socket_id else None,
            process_id=int(process_id) if process_id else None,
        )
    except (NotFoundError, ValueError) as exc:
        raise Http404(str(exc)) from exc
    except ValidationError as exc:
        messages.error(request, _errors_text(exc))
        return redirect("gui-ports")

    error = None
    if request.method == "POST":
        service = {
            key: request.POST.get(key, "").strip()
            for key in (
                "name",
                "category",
                "description",
                "expected_executable",
                "expected_working_directory",
            )
        }
        selected = [int(v) for v in request.POST.getlist("socket_ids") if v.isdigit()]
        try:
            result = adopt.apply(
                machine,
                {
                    "service": service,
                    "socket_ids": selected,
                    "reserve_any_address": request.POST.get("reserve_any_address") == "on",
                },
            )
        except ValidationError as exc:
            error = _errors_text(exc)
            proposal["service"].update(service)
            for endpoint in proposal["endpoints"]:
                endpoint["selected"] = endpoint["socket_id"] in selected
        else:
            svc = result["service"]
            messages.success(
                request,
                f"Service '{svc.name}' registered with {len(result['reservations'])} reservation(s).",
            )
            return redirect("gui-service", pk=svc.pk)
    return render(
        request,
        "portregistry/adopt.html",
        {"proposal": proposal, "error": error, "categories": SUGGESTED_CATEGORIES},
    )


# --------------------------------------------------------- mark as known


@gui_login_required
@require_POST
def mark_socket_known(request: HttpRequest, pk: int) -> HttpResponse:
    try:
        sock = Socket.objects.select_related("process", "machine").get(pk=pk)
    except Socket.DoesNotExist as exc:
        raise Http404("Endpoint not found") from exc
    try:
        rule = ignore_rules.mark_socket_known(sock)
    except ValidationError as exc:
        messages.error(request, _errors_text(exc))
    else:
        messages.success(
            request, f"Added ignore rule '{rule.name}'. Manage rules under Settings → Ignore rules."
        )
    return redirect(_back(request, f"/ports/{pk}/"))


@gui_login_required
@require_POST
def mark_process_known(request: HttpRequest, pk: int) -> HttpResponse:
    try:
        proc = ProcessInstance.objects.select_related("machine").get(pk=pk)
    except ProcessInstance.DoesNotExist as exc:
        raise Http404("Process not found") from exc
    try:
        rule = ignore_rules.mark_process_known(proc)
    except ValidationError as exc:
        messages.error(request, _errors_text(exc))
    else:
        messages.success(request, f"Added ignore rule '{rule.name}'.")
    return redirect(_back(request, f"/processes/{pk}/"))


# ---------------------------------------------------------- ignore rules


@gui_login_required
@require_http_methods(["GET", "POST"])
def ignore_rules_view(request: HttpRequest) -> HttpResponse:
    machine = _machine()
    error = None
    values: dict[str, Any] = {}
    if request.method == "POST":
        values = {
            key: request.POST.get(key, "").strip()
            for key in (
                "name",
                "process_name",
                "exe",
                "protocol",
                "port_min",
                "port_max",
                "address",
            )
        }
        data = dict(values)
        data["suppress_conflicts"] = request.POST.get("suppress_conflicts") == "on"
        data["quiet_history"] = request.POST.get("quiet_history") == "on"
        try:
            rule = ignore_rules.create_rule(machine, data)
        except ValidationError as exc:
            error = _errors_text(exc)
        else:
            messages.success(request, f"Ignore rule '{rule.name}' added.")
            return redirect("gui-ignore-rules")
    rules = list(ignore_rules.list_rules(machine))
    views = {r.pk: ignore_rules.rule_view(r).describe() for r in rules}
    return render(
        request,
        "portregistry/ignore_rules.html",
        {
            "rules": rules,
            "describe": views,
            "error": error,
            "values": values,
            "noise": ignore_rules.noise_settings(),
        },
    )


def _rule(pk: int) -> IgnoreRule:
    try:
        return ignore_rules.get_rule(pk)
    except NotFoundError as exc:
        raise Http404(str(exc)) from exc


@gui_login_required
@require_POST
def ignore_rule_toggle(request: HttpRequest, pk: int) -> HttpResponse:
    rule = _rule(pk)
    ignore_rules.update_rule(rule, {"enabled": not rule.enabled})
    return redirect("gui-ignore-rules")


@gui_login_required
@require_POST
def ignore_rule_delete(request: HttpRequest, pk: int) -> HttpResponse:
    rule = _rule(pk)
    ignore_rules.delete_rule(rule)
    messages.success(request, f"Ignore rule '{rule.name}' removed.")
    return redirect("gui-ignore-rules")


# --------------------------------------------------------------- timeline


@gui_login_required
def timeline_view(request: HttpRequest) -> HttpResponse:
    machine = _machine()
    context: dict[str, Any] = {"params": request.GET}
    if request.GET.get("port"):
        try:
            port, protocol, days = timeline.parse_params(dict(request.GET.items()))
        except ValidationError as exc:
            context["error"] = _errors_text(exc)
        else:
            context["tl"] = timeline.layout(timeline.build_timeline(machine, port, protocol, days))
    return render(request, "portregistry/timeline.html", context)


# ------------------------------------------------------- free-port suggestion


@gui_login_required
def suggest_port(request: HttpRequest) -> HttpResponse:
    """HTMX: put a free port into the reservation form and refresh the check panel."""
    machine = _machine()
    protocol = request.GET.get("protocol", "tcp")
    address = request.GET.get("bind_address", "*")
    port = free_ports.suggest_one(machine, protocol, address)
    findings: list[Any] = []
    error = None
    if port is None:
        error = "No free port found in 3000-9999 for this protocol/address."
    else:
        try:
            findings = reservations.check_reservation(
                machine, {"port": port, "protocol": protocol, "bind_address": address}
            )
        except ValidationError as exc:
            error = _errors_text(exc)
    form = ReservationForm(machine=machine, initial={"port": port})
    return render(
        request,
        "portregistry/partials/suggested_port.html",
        {"field": form["port"], "port": port, "findings": findings, "error": error},
    )


# ------------------------------------------------- onboarding & saved filters


@gui_login_required
@require_POST
def onboarding_dismiss(request: HttpRequest) -> HttpResponse:
    preferences.set_setting("onboarding_dismissed", request.POST.get("show") != "1")
    return redirect(_back(request, "/"))


@gui_login_required
@require_POST
def save_filter(request: HttpRequest) -> HttpResponse:
    page = request.POST.get("page", "")
    try:
        saved = preferences.create_filter(
            _machine(),
            {
                "name": request.POST.get("name", ""),
                "page": page,
                "querystring": request.POST.get("querystring", ""),
            },
        )
    except ValidationError as exc:
        messages.error(request, _errors_text(exc))
        return redirect(_back(request, f"/{page}/" if page else "/"))
    messages.success(request, f"Saved filter '{saved.name}'.")
    return redirect(f"/{saved.page}/?{saved.querystring}")


@gui_login_required
@require_POST
def delete_filter(request: HttpRequest, pk: int) -> HttpResponse:
    try:
        saved = preferences.get_filter(_machine(), pk)
    except NotFoundError as exc:
        raise Http404(str(exc)) from exc
    page = saved.page
    preferences.delete_filter(saved)
    messages.success(request, f"Deleted saved filter '{saved.name}'.")
    return redirect(f"/{page}/")


def saved_filter_links(machine: Any, page: str) -> list[dict[str, Any]]:
    return [
        {"id": f.pk, "name": f.name, "url": f"/{page}/?{f.querystring}"}
        for f in preferences.list_filters(machine, page)
    ]


def querystring_without(request: HttpRequest, *drop: str) -> str:
    return urlencode([(k, v) for k, v in request.GET.items() if k not in drop and v])


# ------------------------------------------------------------- process control


def _stop_params(source: Any) -> tuple[str, bool]:
    mode = "tree" if source.get("mode") == "tree" else "process"
    force = str(source.get("force") or "") in ("1", "true", "on")
    return mode, force


@gui_login_required
@require_http_methods(["GET", "POST"])
def stop_review(request: HttpRequest, pk: int) -> HttpResponse:
    """Review page (GET) and step 1 of the two-step stop (POST issues a 30 s code)."""
    source = request.POST if request.method == "POST" else request.GET
    mode, force = _stop_params(source)
    error = None
    if request.method == "POST":
        try:
            issued = process_control.request_stop(pk, mode=mode, force=force, actor="gui")
        except NotFoundError as exc:
            raise Http404(str(exc)) from exc
        except process_control.ControlError as exc:
            error = exc.message
        else:
            return render(
                request,
                "portregistry/stop_confirm.html",
                {"issued": issued, "a": issued["assessment"]},
            )
    try:
        data = process_control.preview(pk, mode=mode, force=force)
    except NotFoundError as exc:
        raise Http404(str(exc)) from exc
    return render(request, "portregistry/stop_review.html", {"a": data, "error": error})


@gui_login_required
@require_POST
def stop_confirm(request: HttpRequest) -> HttpResponse:
    """Step 2: the code plus the PID typed by the user."""
    process_id = request.POST.get("process_id", "")
    try:
        op = process_control.confirm_stop(
            request.POST.get("code", ""), pid=request.POST.get("pid", ""), actor="gui"
        )
    except NotFoundError as exc:
        raise Http404(str(exc)) from exc
    except process_control.ControlError as exc:
        messages.error(request, f"Nothing was stopped: {exc.message}")
        if process_id.isdigit():
            return redirect("gui-process-stop", pk=int(process_id))
        return redirect("gui-ports")
    return redirect("gui-stop-operation", op_id=op["id"])


@gui_login_required
def stop_operation(request: HttpRequest, op_id: str) -> HttpResponse:
    try:
        op = process_control.get_operation(op_id)
    except NotFoundError as exc:
        raise Http404(str(exc)) from exc
    template = (
        "portregistry/partials/stop_operation.html"
        if request.headers.get("HX-Request")
        else "portregistry/stop_result.html"
    )
    return render(request, template, {"op": op})
