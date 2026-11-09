from django.db import models

from portregistry.django_app.models.observed import PROTOCOL_CHOICES


class DockerImage(models.Model):
    machine = models.ForeignKey("portregistry.Machine", on_delete=models.CASCADE)
    image_id = models.CharField(max_length=128)
    repository = models.CharField(max_length=255, blank=True)
    tag = models.CharField(max_length=128, blank=True)
    digest = models.CharField(max_length=128, blank=True)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()

    class Meta:
        app_label = "portregistry"
        constraints = [
            models.UniqueConstraint(fields=["machine", "image_id"], name="uniq_docker_image")
        ]

    def __str__(self) -> str:
        if self.repository:
            return f"{self.repository}:{self.tag or 'latest'}"
        return self.image_id[:19]


class DockerContainer(models.Model):
    """A container observed through the Docker API (read-only)."""

    machine = models.ForeignKey("portregistry.Machine", on_delete=models.CASCADE)
    container_id = models.CharField(max_length=64)
    name = models.CharField(max_length=255)
    image = models.ForeignKey(DockerImage, null=True, blank=True, on_delete=models.SET_NULL)
    image_ref = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=32)
    created_at_docker = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    labels = models.JSONField(default=dict, blank=True)
    networks = models.JSONField(default=dict, blank=True)
    # present = seen in the latest *successful* inventory.
    present = models.BooleanField(default=True)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    removed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        app_label = "portregistry"
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["machine", "container_id"], name="uniq_docker_container"
            )
        ]

    def __str__(self) -> str:
        return self.name

    @property
    def short_id(self) -> str:
        return self.container_id[:12]


class DockerPortMapping(models.Model):
    """A container port. Internal (exposed) ports and host-published mappings are distinct:
    ``host_port`` is null for ports that are only exposed inside Docker networks."""

    container = models.ForeignKey(
        DockerContainer, on_delete=models.CASCADE, related_name="port_mappings"
    )
    key = models.CharField(max_length=128)
    container_port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=3, choices=PROTOCOL_CHOICES)
    host_ip = models.CharField(max_length=64, blank=True)
    host_port = models.PositiveIntegerField(null=True, blank=True)
    active = models.BooleanField(default=True)

    class Meta:
        app_label = "portregistry"
        ordering = ["container_port", "protocol"]
        constraints = [
            models.UniqueConstraint(fields=["container", "key"], name="uniq_docker_mapping")
        ]
        indexes = [models.Index(fields=["host_port", "protocol"])]

    @property
    def published(self) -> bool:
        return self.host_port is not None
