"""Authentication for the local API.

* CLI/TUI clients send ``Authorization: Bearer <token>`` using the random token
  stored in the permission-restricted ``token`` file.
* Browsers use a Django session (established via a one-time login link or by
  pasting the token on the login page). DRF's SessionAuthentication enforces
  CSRF on unsafe methods.

All authenticated requests act as a single local "owner" user.
"""

from __future__ import annotations

import secrets
from typing import Any

from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from portregistry.core.application import get_application, has_application
from portregistry.services.db import write_transaction

OWNER_USERNAME = "portregistry-owner"


def ensure_owner_user() -> Any:
    User = get_user_model()  # noqa: N806
    with write_transaction():
        user, created = User.objects.get_or_create(username=OWNER_USERNAME)
        if created:
            user.set_unusable_password()
            user.save()
    return user


def get_owner_user() -> Any:
    User = get_user_model()  # noqa: N806
    user = User.objects.filter(username=OWNER_USERNAME).first()
    return user if user is not None else ensure_owner_user()


def token_is_valid(candidate: str | None) -> bool:
    if not candidate or not has_application():
        return False
    expected = get_application().token
    return bool(expected) and secrets.compare_digest(candidate.strip(), expected)


def bearer_token(header: str) -> str | None:
    parts = header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


class LocalTokenAuthentication(BaseAuthentication):
    def authenticate(self, request: Any) -> tuple[Any, None] | None:
        raw = get_authorization_header(request)
        if not raw:
            return None
        try:
            header = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise AuthenticationFailed("Malformed Authorization header.") from exc
        token = bearer_token(header)
        if token is None:
            raise AuthenticationFailed("Use 'Authorization: Bearer <token>'.")
        if not token_is_valid(token):
            raise AuthenticationFailed("Invalid API token.")
        return get_owner_user(), None

    def authenticate_header(self, request: Any) -> str:
        return 'Bearer realm="portregistry"'
