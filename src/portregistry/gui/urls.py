from pathlib import Path

from django.urls import path, re_path
from django.views.static import serve

from portregistry.gui import auth, views
from portregistry.gui import views_extra as vx

STATIC_ROOT = Path(__file__).resolve().parent / "static"

urlpatterns = [
    path("", views.dashboard, name="gui-dashboard"),
    path("login/", auth.login_view, name="gui-login"),
    path("login/link/<str:nonce>/", auth.link_login_view, name="gui-login-link"),
    path("logout/", auth.logout_view, name="gui-logout"),
    path("scan/", views.trigger_scan, name="gui-scan"),
    path("ports/", views.ports, name="gui-ports"),
    path("ports/timeline/", vx.timeline_view, name="gui-timeline"),
    path("ports/<int:pk>/known/", vx.mark_socket_known, name="gui-port-known"),
    path("processes/<int:pk>/known/", vx.mark_process_known, name="gui-process-known"),
    path("processes/<int:pk>/stop/", vx.stop_review, name="gui-process-stop"),
    path("processes/stop/confirm/", vx.stop_confirm, name="gui-stop-confirm"),
    path("processes/stop/<str:op_id>/", vx.stop_operation, name="gui-stop-operation"),
    path("adopt/", vx.adopt_view, name="gui-adopt"),
    path("settings/ignore/", vx.ignore_rules_view, name="gui-ignore-rules"),
    path("settings/ignore/<int:pk>/toggle/", vx.ignore_rule_toggle, name="gui-ignore-toggle"),
    path("settings/ignore/<int:pk>/delete/", vx.ignore_rule_delete, name="gui-ignore-delete"),
    path("reservations/suggest-port/", vx.suggest_port, name="gui-suggest-port"),
    path("onboarding/dismiss/", vx.onboarding_dismiss, name="gui-onboarding-dismiss"),
    path("filters/save/", vx.save_filter, name="gui-filter-save"),
    path("filters/<int:pk>/delete/", vx.delete_filter, name="gui-filter-delete"),
    path("ports/<int:pk>/", views.port_detail, name="gui-port"),
    path("processes/<int:pk>/", views.process_detail, name="gui-process"),
    path("services/", views.services, name="gui-services"),
    path("services/new/", views.service_create, name="gui-service-new"),
    path("services/<int:pk>/", views.service_detail, name="gui-service"),
    path("services/<int:pk>/edit/", views.service_edit, name="gui-service-edit"),
    path("services/<int:pk>/delete/", views.service_delete, name="gui-service-delete"),
    path("reservations/", views.reservations_list, name="gui-reservations"),
    path("reservations/new/", views.reservation_create, name="gui-reservation-new"),
    path("reservations/check/", views.reservation_check, name="gui-reservation-check"),
    path("reservations/<int:pk>/", views.reservation_edit, name="gui-reservation-edit"),
    path(
        "reservations/<int:pk>/release/", views.reservation_release, name="gui-reservation-release"
    ),
    path(
        "reservations/<int:pk>/reactivate/",
        views.reservation_reactivate,
        name="gui-reservation-reactivate",
    ),
    path("reservations/<int:pk>/delete/", views.reservation_delete, name="gui-reservation-delete"),
    path("conflicts/", views.conflicts, name="gui-conflicts"),
    path("history/", views.history, name="gui-history"),
    path("containers/", views.containers, name="gui-containers"),
    path("machine/", views.machine_view, name="gui-machine"),
    path("partials/status-bar/", views.status_bar, name="gui-status-bar"),
    path("partials/dashboard/", views.dashboard_partial, name="gui-dashboard-partial"),
    path("partials/recent-events/", views.recent_events, name="gui-recent-events"),
    # Local single-user app: serve vendored/static assets directly from the package.
    re_path(r"^static/(?P<path>.*)$", serve, {"document_root": STATIC_ROOT}),
]
