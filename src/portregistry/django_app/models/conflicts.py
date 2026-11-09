from django.db import models
from django.db.models import Q


class Conflict(models.Model):
    """A conflict finding produced by the conflict engine.

    Rows are keyed by a stable ``fingerprint``. While a finding persists across
    recomputations the row is updated in place; when it disappears the row is
    marked resolved (kept for history). A later reappearance creates a new row.
    """

    SEVERITY_CHOICES = [("error", "Error"), ("warning", "Warning"), ("info", "Info")]
    CERTAINTY_CHOICES = [("definite", "Definite"), ("potential", "Potential")]

    machine = models.ForeignKey("portregistry.Machine", on_delete=models.CASCADE)
    fingerprint = models.CharField(max_length=200)
    type = models.CharField(max_length=40)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    certainty = models.CharField(max_length=10, choices=CERTAINTY_CHOICES)
    title = models.CharField(max_length=300)
    explanation = models.TextField()
    evidence = models.JSONField(default=dict, blank=True)
    protocol = models.CharField(max_length=3, blank=True)
    port = models.PositiveIntegerField(null=True, blank=True)
    address = models.CharField(max_length=64, blank=True)
    reservation = models.ForeignKey(
        "portregistry.PortReservation",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="conflicts",
    )
    related_reservation = models.ForeignKey(
        "portregistry.PortReservation",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="related_conflicts",
    )
    service = models.ForeignKey(
        "portregistry.Service", null=True, blank=True, on_delete=models.SET_NULL
    )
    socket = models.ForeignKey(
        "portregistry.Socket", null=True, blank=True, on_delete=models.SET_NULL
    )
    process = models.ForeignKey(
        "portregistry.ProcessInstance", null=True, blank=True, on_delete=models.SET_NULL
    )
    active = models.BooleanField(default=True)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        app_label = "portregistry"
        ordering = ["-first_seen"]
        constraints = [
            models.UniqueConstraint(
                fields=["machine", "fingerprint"],
                condition=Q(active=True),
                name="uniq_active_conflict_fingerprint",
            )
        ]
        indexes = [
            models.Index(fields=["machine", "active", "severity"]),
            models.Index(fields=["type"]),
        ]
