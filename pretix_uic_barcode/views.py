import string
from django import forms
from django.http import HttpResponse
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from pretix.base.forms import SettingsForm, SecretKeySettingsField, SECRET_REDACTED
from pretix.base.models import Event
from pretix.base.services.tickets import invalidate_cache
from pretix.base.services.tasks import EventTask
from pretix.celery_app import app
from pretix.control.views.event import EventSettingsFormView, EventSettingsViewMixin
from pretix.control.permissions import administrator_permission_required
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from . import pkpass

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
            ('mmtd', _("MMTD envelope (beta)")),
        ),
        required=True
    )
    uic_barcode_encoding = forms.ChoiceField(
        label=_("Barcode encoding"),
        widget=forms.RadioSelect,
        choices=(
            ('raw', _("Raw bytes - for Aztec barcodes")),
            ('b41', _("Base41 encoded - for QR codes, with optional URL prefix")),
            ('b45', _("Base45 encoded - for QR codes (non-standard)")),
        ),
        required=True
    )
    uic_barcode_qr_url_prefix = forms.URLField(
        label=_("QR Code URL prefix"),
        required=False,
        help_text=_("This field only has an effect on Base41 encoded QR codes. An all caps URL is recommended for QR encoding efficiency."),
    )
    uic_barcode_order_data_in_barcode = forms.BooleanField(
        label=_("Order data in barcode"),
        required=False,
    )
    uic_barcode_order_secret_in_barcode = forms.BooleanField(
        label=_("Order secret in barcode"),
        required=False,
        help_text=_("Warning: this will put the secret required to edit the whole order in the ticket barcode.")
    )
    uic_barcode_order_position_secret_in_barcode = forms.BooleanField(
        label=_("Order position secret in barcode"),
        required=False,
        help_text=_("Warning: this will put the secret required to edit the order position in the ticket barcode.")
    )
    uic_barcode_security_provider_org_code = forms.CharField(
        label=_("ERA Organisation Code/RICS"),
        required=False,
    )
    uic_barcode_security_provider_alt_code_table = forms.CharField(
        label=_("Alternate code table"),
        required=False,
        help_text=_("Leave blank for an entirely private organisation code."),
    )
    uic_barcode_security_provider_alt_code_value = forms.CharField(
        label=_("Alternate value"),
        required=False,
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

    def clean_uic_barcode_security_provider_org_code(self):
        alphabet = string.ascii_uppercase + string.digits
        if self.cleaned_data["uic_barcode_security_provider_org_code"] and len(self.cleaned_data["uic_barcode_security_provider_org_code"]) != 4:
            raise ValidationError(_("Security provider code must be exactly 4 characters."))
        if not all(c in alphabet for c in self.cleaned_data["uic_barcode_security_provider_org_code"]):
            raise ValidationError(_("Security provider code contains invalid characters."))
        return self.cleaned_data["uic_barcode_security_provider_org_code"]

    def clean_uic_barcode_security_provider_alt_code_table(self):
        if len(self.cleaned_data["uic_barcode_security_provider_alt_code_table"]) > 16:
            raise ValidationError(_("Security provider alternate code table must be no more than 16 characters."))
        if not all(32 <= ord(c) <= 126 for c in self.cleaned_data["uic_barcode_security_provider_alt_code_table"]):
            raise ValidationError(_("Security provider alternate code table contains invalid characters."))
        return self.cleaned_data["uic_barcode_security_provider_alt_code_table"]

    def clean_uic_barcode_security_provider_alt_code_value(self):
        if not all(32 <= ord(c) <= 126 for c in self.cleaned_data["uic_barcode_security_provider_alt_code_value"]):
            raise ValidationError(_("Security provider alternate code value contains invalid characters"))
        return self.cleaned_data["uic_barcode_security_provider_alt_code_value"]

    def clean_uic_barcode_key_id(self):
        if not all(32 <= ord(c) <= 126 for c in self.cleaned_data["uic_barcode_key_id"]):
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

        if isinstance(pk, DSAPrivateKey):
            if pk.key_size not in (1024, 2048):
                raise ValidationError(_("DSA key must be 1024-bit or 2048-bit"))

        return pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()

    def clean(self):
        if not self.cleaned_data.get("uic_barcode_security_provider_org_code") and not \
                self.cleaned_data.get("uic_barcode_security_provider_alt_code_value"):
            raise ValidationError(_("One of security provider Organisation Code/RICS or alternate code is required."))
        if self.cleaned_data.get("uic_barcode_security_provider_org_code") and (
                self.cleaned_data.get("uic_barcode_security_provider_alt_code_table") or
                self.cleaned_data.get("uic_barcode_security_provider_alt_code_value")
        ):
            raise ValidationError(_("Only one of security provider Organisation Code/RICS or alternate code is permitted."))

        if self.cleaned_data.get("uic_barcode_security_provider_alt_code_table") and not \
                self.cleaned_data.get("uic_barcode_security_provider_alt_code_value"):
            raise ValidationError(_("Alternate code table and value must both me set."))

        if self.cleaned_data["uic_barcode_format"] == "tlb":
            if not self.cleaned_data.get("uic_barcode_security_provider_org_code"):
                raise ValidationError({
                    "uic_barcode_security_provider_org_code": _("A security provider Organisation Code/RICS is required for TLB barcodes."),
                })
            if len(self.cleaned_data["uic_barcode_key_id"]) > 5:
                raise ValidationError({
                    "uic_barcode_key_id": _("Key ID must be no more than 5 characters long in TLB barcodes"),
                })

            pk_pem = self.cleaned_data["uic_barcode_private_key"] if self.cleaned_data["uic_barcode_private_key"] != SECRET_REDACTED else self.obj.settings.uic_barcode_private_key
            pk = load_pem_private_key(pk_pem.encode(), None)
            if not isinstance(pk, DSAPrivateKey):
                raise ValidationError({
                    "uic_barcode_private_key": _("TLB barcodes require a DSA private key"),
                })

        elif self.cleaned_data["uic_barcode_format"] in ("dosipas", "mmtd"):
            try:
                key_id = int(self.cleaned_data["uic_barcode_key_id"], 10)
                if key_id < 0 or key_id > 99999:
                    raise ValidationError({
                        "uic_barcode_key_id": _("Key ID must be between 0 and 99999"),
                    })
            except ValueError:
                raise ValidationError({
                    "uic_barcode_key_id": _("Key ID must be an integer for non-TLB barcodes"),
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
        regenerate_tickets.apply_async(kwargs={"event": self.request.event.pk})


@app.task(base=EventTask, acks_late=True)
def regenerate_tickets(event: Event):
    invalidate_cache.apply_async(kwargs={"event": event.pk, "provider": "pdf-uic"})
    invalidate_cache.apply_async(kwargs={"event": event.pk, "provider": "apple-wallet-uic"})
    invalidate_cache.apply_async(kwargs={"event": event.pk, "provider": "google-wallet-uic"})
    invalidate_cache.apply_async(kwargs={"event": event.pk, "provider": "raw-uic"})


@administrator_permission_required()
def apple_wallet_csr(request, **kwargs):
    private_key = pkpass.get_private_key()
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Pretix"),
    ])).sign(private_key, hashes.SHA256())
    res = HttpResponse(
        csr.public_bytes(Encoding.PEM),
        content_type="application/pkcs10",

    )
    res['Content-Disposition'] = 'attachment; filename="apple_wallet.csr"'
    return res
