from django.db import models


class Event(models.Model):
    """A meaningful state change (history). Not a polling snapshot.

    Entities are referenced by type/id plus a ``details`` snapshot rather than
    foreign keys, so deleting a service or reservation never deletes history.
    """

    SEVERITY_CHOICES = [("info", "Info"), ("warning", "Warning"), ("error", "Error")]

    machine = models.ForeignKey(
        "portregistry.Machine", null=True, blank=True, on_delete=models.SET_NULL
    )
    timestamp = models.DateTimeField(db_index=True)
    type = models.CharField(max_length=64)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default="info")
    entity_type = models.CharField(max_length=32, blank=True)
    entity_id = models.CharField(max_length=64, blank=True)
    summary = models.CharField(max_length=300)
    details = models.JSONField(default=dict, blank=True)
    # Short-lived/ephemeral or user-ignored churn: hidden by default, purged sooner.
    noise = models.BooleanField(default=False, db_index=True)

    class Meta:
        app_label = "portregistry"
        ordering = ["-timestamp", "-id"]
        indexes = [
            models.Index(fields=["type", "-timestamp"]),
            models.Index(fields=["entity_type", "entity_id"]),
        ]

    def __str__(self) -> str:
        return f"{self.timestamp:%Y-%m-%d %H:%M:%S} {self.type}: {self.summary}"
