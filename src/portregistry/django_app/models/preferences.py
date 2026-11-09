"""User preferences: ignore rules, saved filters and small key/value settings."""

from django.db import models

PROTOCOL_ANY_CHOICES = [("", "Any"), ("tcp", "TCP"), ("udp", "UDP")]


class IgnoreRule(models.Model):
    """Endpoints the user knows about. Matching endpoints are not reported as
    unregistered listeners and their history events are marked as noise.
    Conflicts involving an explicit reservation are never suppressed."""

    machine = models.ForeignKey("portregistry.Machine", on_delete=models.CASCADE)
    name = models.CharField(max_length=120)
    enabled = models.BooleanField(default=True)
    process_name = models.CharField(max_length=255, blank=True)
    exe = models.CharField(max_length=500, blank=True)
    protocol = models.CharField(max_length=3, choices=PROTOCOL_ANY_CHOICES, blank=True)
    port_min = models.PositiveIntegerField(null=True, blank=True)
    port_max = models.PositiveIntegerField(null=True, blank=True)
    address = models.CharField(max_length=64, blank=True)
    suppress_conflicts = models.BooleanField(default=True)
    quiet_history = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "portregistry"
        ordering = ["name", "id"]

    def __str__(self) -> str:
        return self.name


class SavedFilter(models.Model):
    """A named query string for a list page (ports, history, conflicts)."""

    PAGE_CHOICES = [("ports", "Ports"), ("history", "History"), ("conflicts", "Conflicts")]

    machine = models.ForeignKey("portregistry.Machine", on_delete=models.CASCADE)
    name = models.CharField(max_length=80)
    page = models.CharField(max_length=16, choices=PAGE_CHOICES)
    querystring = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "portregistry"
        ordering = ["page", "name"]
        constraints = [
            models.UniqueConstraint(fields=["machine", "page", "name"], name="uniq_saved_filter")
        ]

    def __str__(self) -> str:
        return f"{self.page}: {self.name}"


class Setting(models.Model):
    key = models.CharField(max_length=100, unique=True)
    value = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "portregistry"

    def __str__(self) -> str:
        return self.key
