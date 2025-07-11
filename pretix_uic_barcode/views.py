from django import forms
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from pretix.base.forms import SettingsForm, SecretKeySettingsField, SECRET_REDACTED
from pretix.base.models import Event
from pretix.base.services.tickets import invalidate_cache
from pretix.base.services.tasks import EventTask
from pretix.base.secrets import assign_ticket_secret
from pretix.celery_app import app
from pretix.control.views.event import (
    EventSettingsFormView,
    EventSettingsViewMixin,
)
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PrivateFormat, NoEncryption

class PrivateKeySettingsWidget(forms.Textarea):
    def __init__(self, attrs=None):
        if attrs is None:
            attrs = {}
        self.__reflect_value = False
        super().__init__(attrs)

    def value_from_datadict(self, data, files, name):
        value = super().value_from_datadict(data, files, name)
        self.__reflect_value = value and value != SECRET_REDACTED
        return value

    def get_context(self, name, value, attrs):
        if value and not self.__reflect_value:
            value = SECRET_REDACTED
        return super().get_context(name, value, attrs)


class UICBarcodeSettingsForm(SettingsForm):
    uic_barcode_format = forms.ChoiceField(
        label=_("Barcode format"),
        widget=forms.RadioSelect,
        choices=(
            ('tlb', _("TLB envelope")),
            ('dosipas', _("DOSIPAS envelope")),
        ),
        required=True
    )
    uic_barcode_encoding = forms.ChoiceField(
        label=_("Barcode encoding"),
        widget=forms.RadioSelect,
        choices=(
            ('raw', _("Raw bytes - for Aztec barcodes")),
            ('b45', _("Base45 encoded - for QR codes")),
        ),
        required=True
    )
    uic_barcode_security_provider_rics = forms.IntegerField(
        label=_("Security provider RICS"),
        validators=[
            MinValueValidator(0),
            MaxValueValidator(32000),
        ],
        required=False,
    )
    uic_barcode_security_provider_ia5 = forms.CharField(
        label=_("Security provider IA5"),
        required=False,
        help_text=_("Use this if you don't have a RICS, you should pick a value that's unlikely to result in a collision."),
    )
    uic_barcode_key_id = forms.CharField(
        label=_("Signing key ID"),
        required=True,
    )
    uic_barcode_private_key = SecretKeySettingsField(
        label=_("Private key"),
        required=True,
        widget=PrivateKeySettingsWidget,
        help_text=_("DSA, ECDSA, or Ed25519 private key in PEM format"),
    )

    def clean_uic_barcode_security_provider_ia5(self):
        if not all(ord(c) < 128 for c in self.cleaned_data["uic_barcode_security_provider_ia5"]):
            raise ValidationError(_("Security provider IA5 contains invalid characters"))
        return self.cleaned_data["uic_barcode_security_provider_ia5"]

    def clean_uic_barcode_key_id(self):
        if not all(ord(c) < 128 for c in self.cleaned_data["uic_barcode_key_id"]):
            raise ValidationError(_("Key ID contains invalid characters"))
        return self.cleaned_data["uic_barcode_key_id"]

    def clean_uic_barcode_private_key(self):
        if self.cleaned_data["uic_barcode_private_key"] == SECRET_REDACTED:
            return self.cleaned_data["uic_barcode_private_key"]

        try:
            pk = load_pem_private_key(self.cleaned_data["uic_barcode_private_key"].encode(), None)
        except ValueError:
            raise ValidationError(_("Invalid private key"))

        if not isinstance(pk, DSAPrivateKey) and not isinstance(pk, EllipticCurvePrivateKey) and not isinstance(pk, Ed25519PrivateKey):
            raise ValidationError(_("Must be a DSA, ECDSA, or Ed25519 private key"))

        return pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()

    def clean(self):
        if not self.cleaned_data.get("uic_barcode_security_provider_rics") and not self.cleaned_data.get("uic_barcode_security_provider_ia5"):
            raise ValidationError(_("One of security provider RICS or IA5 is required"))
        if self.cleaned_data.get("uic_barcode_security_provider_rics") and self.cleaned_data.get("uic_barcode_security_provider_ia5"):
            raise ValidationError(_("Only one of security provider RICS or IA5 is permitted"))

        if self.cleaned_data["uic_barcode_format"] == "tlb":
            if not self.cleaned_data.get("uic_barcode_security_provider_rics"):
                raise ValidationError({
                    "uic_barcode_security_provider_rics": _("A security provider RICS is required for TLB barcodes"),
                })
            if self.cleaned_data["uic_barcode_security_provider_rics"] > 9999:
                raise ValidationError({
                    "uic_barcode_security_provider_rics": _("Security provider RICS must be less than or equal to 9999 in TLB barcodes")
                })
            if len(self.cleaned_data["uic_barcode_key_id"]) > 5:
                raise ValidationError({
                    "uic_barcode_key_id": _("Key ID must be less than or equal to 5 characters long in TLB barcodes"),
                })

            pk_pem = self.cleaned_data["uic_barcode_private_key"] if self.cleaned_data["uic_barcode_private_key"] != SECRET_REDACTED else self.obj.settings.uic_barcode_private_key
            pk = load_pem_private_key(pk_pem.encode(), None)
            if not isinstance(pk, DSAPrivateKey):
                raise ValidationError({
                    "uic_barcode_private_key": _("TLB barcodes require a DSA private key"),
                })
        elif self.cleaned_data["uic_barcode_format"] == "dosipas":
            try:
                key_id = int(self.cleaned_data["uic_barcode_key_id"], 10)
                if key_id < 0 or key_id > 99999:
                    raise ValidationError({
                        "uic_barcode_key_id": _("Key ID must be between 0 and 99999"),
                    })
            except ValueError:
                raise ValidationError({
                    "uic_barcode_key_id": _("Key ID must be an integer for DOSIPAS barcodes"),
                })


class SettingsView(EventSettingsViewMixin, EventSettingsFormView):
    model = Event
    form_class = UICBarcodeSettingsForm
    template_name = "pretix_uic_barcode/settings.html"
    permission = "can_change_event_settings"

    def get_success_url(self) -> str:
        return reverse(
            "plugins:pretix_uic_barcode:settings",
            kwargs={
                "organizer": self.request.event.organizer.slug,
                "event": self.request.event.slug,
            },
        )

    def form_success(self):
        regenerate_secrets.apply_async(kwargs={"event": self.request.event.pk})


@app.task(base=EventTask, acks_late=True)
def regenerate_secrets(event: Event):
    for order in event.orders.all():
        for op in order.all_positions.all():
            assign_ticket_secret(event, position=op, force_invalidate=False, save=True)

    invalidate_cache.apply_async(kwargs={"event": event.pk, "provider": "pdf-uic"})