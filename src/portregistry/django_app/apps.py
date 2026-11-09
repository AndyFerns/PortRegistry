from django.apps import AppConfig


class PortRegistryAppConfig(AppConfig):
    name = "portregistry.django_app"
    label = "portregistry"
    verbose_name = "PortRegistry"
    default_auto_field = "django.db.models.BigAutoField"

    # NOTE: ready() intentionally does not start schedulers or discovery.
    # The daemon lifecycle owns all background work.
