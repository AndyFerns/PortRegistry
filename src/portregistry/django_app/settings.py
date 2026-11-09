"""Django settings for the PortRegistry daemon.

Importing this module has no side effects on disk: directories, the secret key
file and the database are created by the daemon lifecycle before Django is set
up. Only the daemon process loads these settings; CLI and TUI clients never
import Django.
"""

from __future__ import annotations

import os
import secrets

from portregistry.config import is_loopback_host, load_config
from portregistry.exceptions import ConfigError
from portregistry.paths import get_paths

PATHS = get_paths()
try:
    _CONFIG = load_config(PATHS)
except ConfigError:
    # The daemon validates configuration before Django starts; tolerate here so
    # that management commands and tests can still import settings.
    _CONFIG = None


def _secret_key() -> str:
    env = os.environ.get("PORTREGISTRY_SECRET_KEY")
    if env:
        return env
    try:
        value = PATHS.secret_key_file.read_text(encoding="utf-8").strip()
        if value:
            return value
    except OSError:
        pass
    # Ephemeral key (tests / management commands). Sessions do not survive restarts.
    return secrets.token_urlsafe(50)


SECRET_KEY = _secret_key()
DEBUG = False

ALLOWED_HOSTS = ["127.0.0.1", "localhost", "[::1]"]
if _CONFIG is not None and not is_loopback_host(_CONFIG.daemon.host):
    ALLOWED_HOSTS.append(_CONFIG.daemon.host)

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "rest_framework",
    "portregistry.django_app.apps.PortRegistryAppConfig",
    "portregistry.gui.apps.GuiConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "portregistry.gui.middleware.SecurityHeadersMiddleware",
]

ROOT_URLCONF = "portregistry.django_app.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "portregistry.gui.context.daemon_context",
            ],
        },
    },
]

ASGI_APPLICATION = "portregistry.django_app.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": str(PATHS.database),
        "OPTIONS": {
            # Busy timeout (seconds) so readers/writers wait instead of failing.
            "timeout": 10,
            # Take the write lock at BEGIN to avoid deadlocking lock upgrades.
            "transaction_mode": "IMMEDIATE",
            # WAL for reader/writer coexistence. Django enables foreign keys itself.
            "init_command": (
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=10000;"
            ),
        },
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True

STATIC_URL = "/static/"

LOGIN_URL = "/login/"

# Cookies are not isolated by port, so use distinctive names on localhost.
SESSION_COOKIE_NAME = "portregistry_session"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_AGE = 7 * 24 * 3600
CSRF_COOKIE_NAME = "portregistry_csrftoken"
CSRF_COOKIE_SAMESITE = "Strict"

X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"

# Sensible request-size limits for a local API.
DATA_UPLOAD_MAX_MEMORY_SIZE = 256 * 1024
DATA_UPLOAD_MAX_NUMBER_FIELDS = 200

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "portregistry.django_app.api.auth.LocalTokenAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_PAGINATION_CLASS": "portregistry.django_app.api.pagination.Pagination",
    "EXCEPTION_HANDLER": "portregistry.django_app.api.errors.exception_handler",
    "UNAUTHENTICATED_USER": "django.contrib.auth.models.AnonymousUser",
}

LOGGING = {"version": 1, "disable_existing_loggers": False}
