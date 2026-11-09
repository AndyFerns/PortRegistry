"""Template context shared by every GUI page."""

from __future__ import annotations

from typing import Any

from django.http import HttpRequest

from portregistry import __version__
from portregistry.core.application import get_application, has_application


def daemon_context(request: HttpRequest) -> dict[str, Any]:
    context: dict[str, Any] = {"pr_version": __version__, "pr_docker": None, "pr_native": None}
    if has_application():
        app = get_application()
        context["pr_docker"] = app.docker_provider.as_dict()
        context["pr_native"] = app.native_provider.as_dict()
        context["pr_native_interval"] = app.config.discovery.native_interval
    return context
