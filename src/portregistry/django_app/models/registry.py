from django.db import models
from django.db.models.functions import Lower

from portregistry.django_app.models.observed import PROTOCOL_CHOICES


class Service(models.Model):
    """A user-declared service. Independent of whether its process is running."""

    machine = models.ForeignKey("portregistry.Machine", on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=50, blank=True)
    expected_executable = models.CharField(max_length=500, blank=True)
    expected_working_directory = models.CharField(max_length=500, blank=True)
    documentation_url = models.URLField(max_length=500, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "portregistry"
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(Lower("name"), "machine", name="uniq_service_name_ci"),
        ]
        indexes = [models.Index(fields=["name"])]

    def __str__(self) -> str:
        return self.name


class PortReservation(models.Model):
    """An advisory claim on protocol/address/port. Never an OS-level lock."""

    STATUS_CHOICES = [("active", "Active"), ("released", "Released")]

    machine = models.ForeignKey("portregistry.Machine", on_delete=models.CASCADE)
    service = models.ForeignKey(
        Service,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reservations",
    )
    port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=3, choices=PROTOCOL_CHOICES, default="tcp")
    bind_address = models.CharField(max_length=64, default="*")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="active")
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    released_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        app_label = "portregistry"
        ordering = ["port", "protocol", "id"]
        indexes = [
            models.Index(fields=["machine", "port", "protocol"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self) -> str:
        host = f"[{self.bind_address}]" if ":" in self.bind_address else self.bind_address
        return f"{self.protocol} {host}:{self.port}"
