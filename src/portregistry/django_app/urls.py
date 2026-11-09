from django.urls import include, path

urlpatterns = [
    path("api/v1/", include("portregistry.django_app.api.urls")),
    path("", include("portregistry.gui.urls")),
]
