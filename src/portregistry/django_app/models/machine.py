from django.db import models


class Machine(models.Model):
    """A host known to PortRegistry. The MVP only manages the local machine."""

    uuid = models.UUIDField(unique=True)
    hostname = models.CharField(max_length=255)
    os_name = models.CharField(max_length=64, blank=True)
    os_version = models.CharField(max_length=128, blank=True)
    os_detail = models.CharField(max_length=255, blank=True)
    architecture = models.CharField(max_length=64, blank=True)
    is_local = models.BooleanField(default=True)
    online = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(null=True, blank=True)

    class Meta:
        app_label = "portregistry"
        ordering = ["hostname"]

    def __str__(self) -> str:
        return f"{self.hostname} ({self.uuid})"
