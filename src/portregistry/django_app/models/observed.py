from django.db import models
from django.db.models import Q

PROTOCOL_CHOICES = [("tcp", "TCP"), ("udp", "UDP")]
FAMILY_CHOICES = [("ipv4", "IPv4"), ("ipv6", "IPv6")]


class DiscoveryScan(models.Model):
    """One discovery run (native socket scan or Docker inventory)."""

    KIND_CHOICES = [("native", "Native sockets"), ("docker", "Docker inventory")]
    STATUS_CHOICES = [
        ("running", "Running"),
        ("complete", "Complete"),
        ("partial", "Partial"),
        ("failed", "Failed"),
    ]

    machine = models.ForeignKey("portregistry.Machine", on_delete=models.CASCADE)
    kind = models.CharField(max_length=16, choices=KIND_CHOICES, default="native")
    trigger = models.CharField(max_length=16, default="scheduled")
    provider = models.CharField(max_length=32, blank=True)
    scope_protocols = models.CharField(max_length=16, default="tcp,udp")
    scope_port = models.PositiveIntegerField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="running")
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField(null=True, blank=True)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    socket_count = models.PositiveIntegerField(default=0)
    process_count = models.PositiveIntegerField(default=0)
    resolved_process_count = models.PositiveIntegerField(default=0)
    resolution_failures = models.PositiveIntegerField(default=0)
    unknown_owner_count = models.PositiveIntegerField(default=0)
    container_count = models.PositiveIntegerField(default=0)
    appeared_count = models.PositiveIntegerField(default=0)
    disappeared_count = models.PositiveIntegerField(default=0)
    errors = models.JSONField(default=list, blank=True)
    message = models.TextField(blank=True)

    class Meta:
        app_label = "portregistry"
        ordering = ["-started_at"]
        indexes = [models.Index(fields=["machine", "kind", "-started_at"])]

    @property
    def is_finished(self) -> bool:
        return self.status != "running"


class ProcessInstance(models.Model):
    """An observed process, identified by machine + PID + creation time."""

    machine = models.ForeignKey("portregistry.Machine", on_delete=models.CASCADE)
    identity_key = models.CharField(max_length=80)
    identity_hash = models.CharField(max_length=64, blank=True)
    identity_complete = models.BooleanField(default=True)
    pid = models.PositiveIntegerField()
    create_time = models.FloatField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    name = models.CharField(max_length=255, blank=True)
    exe = models.TextField(blank=True)
    cmdline = models.JSONField(null=True, blank=True)
    username = models.CharField(max_length=255, blank=True)
    ppid = models.PositiveIntegerField(null=True, blank=True)
    cwd = models.TextField(blank=True)
    project_name = models.CharField(max_length=255, blank=True)
    project_root = models.TextField(blank=True)
    metadata_errors = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    active = models.BooleanField(default=True)
    ended_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        app_label = "portregistry"
        ordering = ["pid"]
        constraints = [
            models.UniqueConstraint(
                fields=["machine", "identity_key"], name="uniq_process_identity_key"
            ),
            models.UniqueConstraint(
                fields=["machine", "pid", "create_time"],
                condition=Q(create_time__isnull=False),
                name="uniq_process_machine_pid_ctime",
            ),
        ]
        indexes = [
            models.Index(fields=["machine", "pid"]),
            models.Index(fields=["name"]),
            models.Index(fields=["machine", "active"]),
        ]

    def __str__(self) -> str:
        return f"{self.name or '?'} (pid {self.pid})"

    @property
    def display_name(self) -> str:
        return self.name or (self.exe.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] if self.exe else "?")


class Socket(models.Model):
    """A locally bound endpoint (TCP listener or bound UDP socket).

    One row per (endpoint, owning process instance) lifetime. Unchanged polling
    cycles only update ``last_seen``/``last_scan``; changes produce history events.
    """

    machine = models.ForeignKey("portregistry.Machine", on_delete=models.CASCADE)
    process = models.ForeignKey(
        "portregistry.ProcessInstance",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="sockets",
    )
    key = models.CharField(max_length=255)
    protocol = models.CharField(max_length=3, choices=PROTOCOL_CHOICES)
    family = models.CharField(max_length=4, choices=FAMILY_CHOICES)
    address = models.CharField(max_length=64)
    port = models.PositiveIntegerField()
    state = models.CharField(max_length=16)
    pid = models.PositiveIntegerField(null=True, blank=True)
    active = models.BooleanField(default=True)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    ended_at = models.DateTimeField(null=True, blank=True)
    first_scan = models.ForeignKey(
        DiscoveryScan, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    last_scan = models.ForeignKey(
        DiscoveryScan, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    class Meta:
        app_label = "portregistry"
        ordering = ["port", "protocol", "address"]
        constraints = [
            models.UniqueConstraint(fields=["machine", "key"], name="uniq_socket_key"),
        ]
        indexes = [
            models.Index(fields=["machine", "port", "protocol"]),
            models.Index(fields=["machine", "active"]),
            models.Index(fields=["pid"]),
        ]

    def __str__(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"{self.protocol} {host}:{self.port}"
