"""Browser login: single-use link or API token -> Django session."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from django.contrib.auth import login, logout
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_http_methods, require_POST

from portregistry.core.application import get_application, has_application
from portregistry.django_app.api.auth import get_owner_user, token_is_valid


def gui_login_required(view: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
    @functools.wraps(view)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not request.user.is_authenticated:
            if request.headers.get("HX-Request"):
                # Partial request after the session expired: ask htmx to reload the page.
                response = HttpResponse(status=401)
                response["HX-Redirect"] = "/login/"
                return response
            return redirect(f"/login/?next={request.get_full_path()}")
        return view(request, *args, **kwargs)

    return wrapper


def _safe_next(request: HttpRequest, value: str | None) -> str:
    if value and url_has_allowed_host_and_scheme(
        value, allowed_hosts={request.get_host()}, require_https=False
    ):
        return value
    return "/"


@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    error = None
    next_url = _safe_next(request, request.GET.get("next") or request.POST.get("next"))
    if request.method == "POST":
        if token_is_valid(request.POST.get("token")):
            login(request, get_owner_user(), backend="django.contrib.auth.backends.ModelBackend")
            return HttpResponseRedirect(next_url)
        error = "That token is not valid."
    token_path = get_application().config.paths.token_file if has_application() else None
    return render(
        request,
        "portregistry/login.html",
        {"error": error, "next": next_url, "token_path": token_path},
        status=401 if error else 200,
    )


def link_login_view(request: HttpRequest, nonce: str) -> HttpResponse:
    if has_application() and get_application().links.consume(nonce):
        login(request, get_owner_user(), backend="django.contrib.auth.backends.ModelBackend")
        return HttpResponseRedirect("/")
    return render(
        request,
        "portregistry/login.html",
        {
            "error": "This login link is invalid, expired or already used. "
            "Run `portregistry gui` for a new one.",
            "next": "/",
            "token_path": get_application().config.paths.token_file if has_application() else None,
        },
        status=401,
    )


@require_POST
def logout_view(request: HttpRequest) -> HttpResponse:
    logout(request)
    return redirect("/login/")
