"""Persistence models.

Observed machine state (processes, sockets, scans, Docker) is kept separate from
user intent (services, reservations). History events reference entities by id
and keep a details snapshot, so deleting user records never deletes history.
"""

from portregistry.django_app.models.conflicts import Conflict
from portregistry.django_app.models.docker import DockerContainer, DockerImage, DockerPortMapping
from portregistry.django_app.models.events import Event
from portregistry.django_app.models.machine import Machine
from portregistry.django_app.models.observed import DiscoveryScan, ProcessInstance, Socket
from portregistry.django_app.models.preferences import IgnoreRule, SavedFilter, Setting
from portregistry.django_app.models.registry import PortReservation, Service

__all__ = [
    "Conflict",
    "DiscoveryScan",
    "DockerContainer",
    "DockerImage",
    "DockerPortMapping",
    "Event",
    "IgnoreRule",
    "Machine",
    "PortReservation",
    "ProcessInstance",
    "SavedFilter",
    "Service",
    "Setting",
    "Socket",
]
