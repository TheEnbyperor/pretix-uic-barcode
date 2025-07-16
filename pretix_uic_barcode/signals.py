from . import secrets, elements, event_settings
from django.dispatch import receiver
from django.urls import resolve, reverse
from django.utils.translation import gettext, gettext_lazy as _
from pretix.base.signals import register_ticket_secret_generators, register_ticket_outputs, api_event_settings_fields, EventPluginSignal
from pretix.control.signals import nav_event_settings

register_barcode_element_generators = EventPluginSignal()


@receiver(register_ticket_secret_generators, dispatch_uid="ticket_generator_uic_barcode")
def secret_generator(sender, **kwargs):
    return [secrets.UICSecretGenerator]


@receiver(api_event_settings_fields, dispatch_uid="api_event_settings_uic_barcode")
def api_settings(sender, **kwargs):
    return event_settings.event_settings_fields()


@receiver(nav_event_settings, dispatch_uid="nav_settings_uic_barcode")
def navbar_settings(sender, request, **kwargs):
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

@receiver(register_barcode_element_generators, dispatch_uid="barcode_element_generator_pretix_data")
def element_generator(sender, **kwargs):
    return [elements.PretixDataBarcodeElementGenerator]

@receiver(register_ticket_outputs, dispatch_uid="output_pdf_uic_barcode")
def register_ticket_outputs(sender, **kwargs):
    from .ticket_output import PdfTicketOutput
    return PdfTicketOutput