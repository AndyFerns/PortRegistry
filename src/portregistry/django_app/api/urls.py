from django.urls import path, re_path

from portregistry.django_app.api import views
from portregistry.django_app.api.errors import api_not_found
from portregistry.django_app.api.sse import event_stream

urlpatterns = [
    path("health/", views.HealthView.as_view(), name="api-health"),
    path("status/", views.StatusView.as_view(), name="api-status"),
    path("daemon/shutdown/", views.ShutdownView.as_view(), name="api-shutdown"),
    path("auth/gui-link/", views.GuiLinkView.as_view(), name="api-gui-link"),
    path("machines/", views.MachineListView.as_view(), name="api-machines"),
    path("machines/<str:machine_uuid>/", views.MachineDetailView.as_view(), name="api-machine"),
    path("ports/", views.PortListView.as_view(), name="api-ports"),
    path("ports/<int:pk>/", views.PortDetailView.as_view(), name="api-port"),
    path("processes/", views.ProcessListView.as_view(), name="api-processes"),
    path("processes/<int:pk>/", views.ProcessDetailView.as_view(), name="api-process"),
    path("containers/", views.ContainerListView.as_view(), name="api-containers"),
    path("containers/<str:ref>/", views.ContainerDetailView.as_view(), name="api-container"),
    path("services/", views.ServiceListView.as_view(), name="api-services"),
    path("services/<str:ref>/", views.ServiceDetailView.as_view(), name="api-service"),
    path("reservations/", views.ReservationListView.as_view(), name="api-reservations"),
    path("reservations/check/", views.ReservationCheckView.as_view(), name="api-reservation-check"),
    path("reservations/<int:pk>/", views.ReservationDetailView.as_view(), name="api-reservation"),
    path(
        "reservations/<int:pk>/release/",
        views.ReservationReleaseView.as_view(),
        name="api-reservation-release",
    ),
    path("conflicts/", views.ConflictListView.as_view(), name="api-conflicts"),
    path("discovery/scan/", views.ScanRequestView.as_view(), name="api-scan"),
    path("discovery/scan/<int:ticket_id>/", views.ScanTicketView.as_view(), name="api-scan-ticket"),
    path("discovery/scans/", views.ScanListView.as_view(), name="api-scans"),
    path("discovery/scans/<int:pk>/", views.ScanDetailView.as_view(), name="api-scan-detail"),
    path("history/", views.HistoryView.as_view(), name="api-history"),
    path("events/stream/", event_stream, name="api-events"),
    re_path(r"^.*$", api_not_found),
]
