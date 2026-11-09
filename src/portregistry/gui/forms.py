"""Django forms for rendering; validation rules live in the services layer."""

from __future__ import annotations

from django import forms

from portregistry.django_app.models import Service
from portregistry.exceptions import ValidationError


class ServiceForm(forms.Form):
    name = forms.CharField(max_length=100)
    category = forms.CharField(max_length=50, required=False)
    description = forms.CharField(widget=forms.Textarea(attrs={"rows": 2}), required=False)
    expected_executable = forms.CharField(
        max_length=500,
        required=False,
        help_text="Program name (e.g. postgres), full path, or docker:NAME for a container/image.",
    )
    expected_working_directory = forms.CharField(max_length=500, required=False)
    documentation_url = forms.CharField(max_length=500, required=False, label="Documentation URL")
    notes = forms.CharField(widget=forms.Textarea(attrs={"rows": 3}), required=False)


class ReservationForm(forms.Form):
    port = forms.IntegerField(min_value=1, max_value=65535)
    protocol = forms.ChoiceField(choices=[("tcp", "TCP"), ("udp", "UDP")], initial="tcp")
    bind_address = forms.CharField(
        max_length=64,
        initial="*",
        help_text="* = any address in both families, or 0.0.0.0, ::, 127.0.0.1, ...",
    )
    service = forms.ModelChoiceField(
        queryset=Service.objects.none(), required=False, empty_label="(no service)"
    )
    description = forms.CharField(widget=forms.Textarea(attrs={"rows": 2}), required=False)

    def __init__(self, *args: object, machine: object = None, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        qs = Service.objects.order_by("name")
        if machine is not None:
            qs = qs.filter(machine=machine)
        self.fields["service"].queryset = qs  # type: ignore[attr-defined]

    def to_payload(self) -> dict[str, object]:
        data = dict(self.cleaned_data)
        service = data.pop("service", None)
        data["service"] = service.pk if service else None
        return data


def apply_errors(form: forms.Form, exc: ValidationError) -> None:
    """Copy service-layer field errors onto a bound form."""
    for field, messages in exc.field_errors.items():
        target = field if field in form.fields else None
        for message in messages:
            form.add_error(target, message)
    if not exc.field_errors:
        form.add_error(None, exc.message)
