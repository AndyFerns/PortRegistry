"""ASGI entry point. Used by the daemon; importing it does not start any background work."""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "portregistry.django_app.settings")

application = get_asgi_application()
