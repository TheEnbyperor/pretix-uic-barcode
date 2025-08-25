import collections
from django.utils.safestring import mark_safe
from django.dispatch import receiver
from django.urls import resolve, reverse
from django.utils.translation import gettext_lazy as _
from django import forms
from pretix.base.signals import EventPluginSignal, register_ticket_secret_generators, register_ticket_outputs, api_event_settings_fields, \
    register_global_settings, order_approved, order_denied, order_expired, order_modified, order_changed, order_paid
from pretix.control.signals import nav_event_settings
from pretix.api.signals import orderposition_api_details
from . import secrets, elements, event_settings, ticket_output, ticket_output_pdf, ticket_output_apple_wallet, ticket_output_google_wallet
from .forms import AppleWalletCertificateFileField

register_barcode_element_generators = EventPluginSignal()
register_vas_element_generators = EventPluginSignal()
generate_google_wallet_module = EventPluginSignal()
generate_apple_wallet_module = EventPluginSignal()


@receiver(register_ticket_secret_generators, dispatch_uid="ticket_generator_uic_barcode")
def secret_generator(sender, **kwargs):
    return [secrets.UICSecretGenerator]


@receiver(api_event_settings_fields, dispatch_uid="api_event_settings_uic_barcode")
def api_settings(sender, **kwargs):
    return event_settings.event_settings_fields()



@receiver(orderposition_api_details, dispatch_uid="api_order_position_uic_barcode")
def api_order_position(sender, orderposition, **kwargs):
    return event_settings.order_position_fields(orderposition)


@receiver(nav_event_settings, dispatch_uid="nav_settings_uic_barcode")
def navbar_settings(sender, request, **kwargs):
    if sender.settings.ticket_secret_generator == "uic-barcodes":
        url = resolve(request.path_info)
        return [
            {
                "label": _("UIC Barcode"),
                "url": reverse(
                    "plugins:pretix_uic_barcode:settings",
                    kwargs={
                        "event": request.event.slug,
                        "organizer": request.organizer.slug,
                    },
                ),
                "active": url.namespace == "plugins:pretix_uic_barcode"
                          and url.url_name.startswith("settings"),
            }
        ]
    else:
        return []


@receiver(register_barcode_element_generators, dispatch_uid="barcode_element_generator_pretix_data")
def uic_element_generator(sender, **kwargs):
    return [elements.PretixDataBarcodeElementGenerator]


@receiver(register_vas_element_generators, dispatch_uid="vas_element_generator_pretix_data")
def vas_element_generator(sender, **kwargs):
    return [elements.PretixDataBarcodeElementGenerator]


@receiver(register_ticket_outputs, dispatch_uid="ticket_output_uic_barcode_pdf")
def register_ticket_output_pdf(sender, **kwargs):
    return ticket_output_pdf.PdfTicketOutput


@receiver(register_ticket_outputs, dispatch_uid="ticket_output_uic_barcode_apple_wallet")
def register_ticket_outputs_apple_wallet(sender, **kwargs):
    return ticket_output_apple_wallet.AppleWalletOutput


@receiver(register_ticket_outputs, dispatch_uid="ticket_output_uic_barcode_google_wallet")
def register_ticket_outputs_google_wallet(sender, **kwargs):
    return ticket_output_google_wallet.GoogleWalletOutput


@receiver(register_global_settings, dispatch_uid="uic_barcode_settings")
def register_global_settings(sender, **kwargs):
    csr_url = reverse("plugins:pretix_uic_barcode:apple_wallet_csr")

    return collections.OrderedDict([
        ("uic_barcode_apple_wallet_certificate", AppleWalletCertificateFileField(
            label=_("Apple Wallet signing certificate"),
            required=False,
            help_text=mark_safe(f"Download the CSR for Apple to sign <a href=\"{csr_url}\">here</a>.")
        )),
        ("uic_barcode_google_wallet_credentials", forms.CharField(
            label=_("Google Wallet service account credentials"),
            required=False,
            widget=forms.Textarea(),
        ))
    ])


@receiver(order_paid, dispatch_uid="uic_barcode_order_paid")
def order_paid(sender, order, **kwargs):
    ticket_output.update_ticket_output_all.apply_async(kwargs={"event": sender.pk, "order_pk": order.pk})


@receiver(order_approved, dispatch_uid="uic_barcode_order_approved")
def order_approved(sender, order, **kwargs):
    ticket_output.update_ticket_output_all.apply_async(kwargs={"event": sender.pk, "order_pk": order.pk})


@receiver(order_denied, dispatch_uid="uic_barcode_order_denied")
def order_denied(sender, order, **kwargs):
    ticket_output.update_ticket_output_all.apply_async(kwargs={"event": sender.pk, "order_pk": order.pk})


@receiver(order_expired, dispatch_uid="uic_barcode_order_expired")
def order_expired(sender, order, **kwargs):
    ticket_output.update_ticket_output_all.apply_async(kwargs={"event": sender.pk, "order_pk": order.pk})


@receiver(order_modified, dispatch_uid="uic_barcode_order_modified")
def order_modified(sender, order, **kwargs):
    ticket_output.update_ticket_output_all.apply_async(kwargs={"event": sender.pk, "order_pk": order.pk})


@receiver(order_changed, dispatch_uid="uic_barcode_order_changed")
def order_changed(sender, order, **kwargs):
    ticket_output.update_ticket_output_all.apply_async(kwargs={"event": sender.pk, "order_pk": order.pk})