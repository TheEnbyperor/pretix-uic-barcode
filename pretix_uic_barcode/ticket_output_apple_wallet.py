import json
import typing
import collections
import urllib.parse
import urllib3
import idna
import pytz
from django import forms
from django.conf import settings
from django.contrib.staticfiles import finders
from django.core.files.storage import default_storage
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _
from pretix.base.models import Order, OrderPosition
from pretix.base.ticketoutput import BaseTicketOutput
from pretix.multidomain.urlreverse import build_absolute_uri
from . import pkpass, barcode


def idna_encode_url(url: str):
    parts = urllib3.util.parse_url(url)
    host = idna.encode(parts.host).decode()
    new_url = urllib3.util.Url(parts.scheme, parts.auth, host, parts.port, parts.path, parts.query, parts.fragment)
    return new_url.url


class AppleWalletOutput(BaseTicketOutput):
    identifier = "apple-wallet-uic"
    verbose_name = "Apple Wallet"
    download_button_icon = "fa-mobile"
    download_button_text = _("Apple Wallet")
    multi_download_enabled = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.signer = pkpass.get_signer()
        self.barcode_generator = barcode.UICBarcodeGenerator(self.event)

    @property
    def settings_form_fields(self) -> dict:
        return collections.OrderedDict(
            list(super().settings_form_fields.items())
            + [("bg_color", forms.CharField(
                label=_("Background color"),
                validators=[
                    RegexValidator(regex="^#[0-9a-fA-F]{6}$", message=_(
                        "Please enter the hexadecimal code of a color, e.g. #990000."
                    )),
                ],
                required=False,
                widget=forms.TextInput(attrs={
                    "class": "colorpickerfield no-contrast",
                    "placeholder": "#RRGGBB",
                }),
            )), ("fg_color", forms.CharField(
                label=_("Text color"),
                validators=[
                    RegexValidator(regex="^#[0-9a-fA-F]{6}$", message=_(
                        "Please enter the hexadecimal code of a color, e.g. #990000."
                    )),
                ],
                required=False,
                widget=forms.TextInput(attrs={
                    "class": "colorpickerfield no-contrast",
                    "placeholder": "#RRGGBB",
                }),
            )), ("label_color", forms.CharField(
                label=_("Label color"),
                validators=[
                    RegexValidator(regex="^#[0-9a-fA-F]{6}$", message=_(
                        "Please enter the hexadecimal code of a color, e.g. #990000."
                    )),
                ],
                required=False,
                widget=forms.TextInput(attrs={
                    "class": "colorpickerfield no-contrast",
                    "placeholder": "#RRGGBB",
                }),
            ))]
        )

    def _generate_pass(self, position: OrderPosition) -> pkpass.PKPass:
        pk_pass = pkpass.PKPass()
        order = position.order
        event = position.subevent or position.order.event
        tz = pytz.timezone(order.event.settings.timezone)

        pass_json = {
            "formatVersion": 1,
            "organizationName": self.signer.pass_signer_name,
            "passTypeIdentifier": self.signer.pass_type_id,
            "teamIdentifier": self.signer.team_id,
            "serialNumber": f"{order.event.organizer.slug}-{position.code}",
            "groupingIdentifier": f"{order.event.organizer.slug}-{order.code}",
            "description": str(event.name),
            "suppressStripShine": True,
            "suppressHeaderDarkening": True,
            "locations": [],
            "webServiceURL": idna_encode_url(urllib.parse.urljoin(settings.SITE_URL, "/api/apple_wallet")),
            "authenticationToken": position.web_secret,
            "eventTicket": {
                "headerFields": [],
                "primaryFields": [],
                "secondaryFields": [],
                "auxiliaryFields": [],
                "backFields": []
            },
            "barcodes": [],
            "voided": bool(position.blocked),
        }

        op_secret = self.barcode_generator.generate_barcode(position)
        if self.event.settings.uic_barcode_encoding == "b45":
            pass_json["barcodes"].append({
                "format": "PKBarcodeFormatQR",
                "message": op_secret.decode("utf-8"),
                "messageEncoding": "utf-8",
                "altText": position.secret,
            })
        else:
            pass_json["barcodes"].append({
                "format": "PKBarcodeFormatAztec",
                "message": op_secret.decode("iso-8859-1"),
                "messageEncoding": "iso-8859-1",
                "altText": position.secret,
            })

        if position.valid_from:
            date_from = position.valid_from.astimezone(tz)
        else:
            date_from = event.date_from.astimezone(tz)
        if position.valid_until:
            date_to = position.valid_until.astimezone(tz)
        elif event.date_to:
            date_to = event.date_to.astimezone(tz)
        else:
            date_to = None

        pass_json["relevantDate"] = date_from.isoformat()
        if position.item.admission:
            pass_json["eventTicket"]["auxiliaryFields"].append({
                "key": "ev-from",
                "label": "From",
                "dateStyle": "PKDateStyleMedium",
                "timeStyle": "PKDateStyleShort",
                "value": date_from.isoformat(),
                "ignoresTimeZone": True
            })

        if date_to:
            pass_json["expirationDate"] = date_to.isoformat()
            if position.item.admission:
                pass_json["eventTicket"]["auxiliaryFields"].append({
                    "key": "ev-to",
                    "label": "To",
                    "dateStyle": "PKDateStyleMedium",
                    "timeStyle": "PKDateStyleShort",
                    "value": date_to.isoformat(),
                    "ignoresTimeZone": True
                })

        pass_json["eventTicket"]["primaryFields"].append({
            "key": "ev-name",
            "label": "Event",
            "value": str(event.name),
        })

        product_name = str(position.item.name)
        if position.variation:
            product_name += " - " + str(position.variation)
        pass_json["eventTicket"]["secondaryFields"].append({
            "key": "ev-product",
            "label": "Product",
            "value": product_name,
        })

        pass_json["eventTicket"]["headerFields"].append({
            "key": "ev-date",
            "value": event.date_from.astimezone(tz).isoformat(),
            "dateStyle": "PKDateStyleShort",
            "timeStyle": "PKDateStyleShort",
            "ignoresTimeZone": True
        })

        if event.geo_lat and event.geo_lon:
            pass_json["locations"].append({
                "latitude": float(event.geo_lat),
                "longitude": float(event.geo_lon),
            })

        pass_json["eventTicket"]["backFields"].append({
            "key": "ev-organizer",
            "label": "Organizer",
            "value": str(order.event.organizer),
        })
        pass_json["eventTicket"]["backFields"].append({
            "key": "order-code",
            "label": "Order code",
            "value": position.code,
        })
        pass_json["eventTicket"]["backFields"].append({
            "key": "order-date",
            "label": "Purchase date",
            "value": order.datetime.astimezone(tz).isoformat(),
            "dateStyle": "PKDateStyleLong",
            "timeStyle": "PKDateStyleLong",
        })

        if position.subevent:
            event_url = build_absolute_uri(order.event, "presale:event.index", {"subevent": position.subevent.pk})
        else:
            event_url = build_absolute_uri(order.event, "presale:event.index")
        pass_json["eventTicket"]["backFields"].append({
            "key": "website",
            "label": "Website",
            "attributedValue": f"<a href=\"{event_url}\">{event_url.replace('https://', '')}</a>",
        })

        if bg_color := self.settings.get("bg_color", None):
            pass_json["backgroundColor"] = bg_color
        if fg_color := self.settings.get("fg_color", None):
            pass_json["foregroundColor"] = fg_color
        if label_color := self.settings.get("label_color", None):
            pass_json["labelColor"] = label_color

        print(pass_json)

        if icon_file := self.settings.get("icon_file", None):
            pk_pass.add_file("icon.png", default_storage.open(icon_file.name, "rb").read())
        else:
            pk_pass.add_file("icon.png", open(finders.find("pretix_uic_barcode/icon.png"), "rb").read())

        pk_pass.add_file("pass.json", json.dumps(pass_json).encode("utf-8"))
        pk_pass.sign(self.signer)
        return pk_pass

    def generate(self, position: OrderPosition) -> typing.Tuple[str, str, bytes]:
        pk_pass = self._generate_pass(position)
        return f"pass_{self.event.slug}_{position.order.code}.pkpass", "application/vnd.apple.pkpass", pk_pass.get_buffer()

    def generate_order(self, order: Order) -> typing.Tuple[str, str, bytes]:
        multi_pk_pass = pkpass.MultiPKPass()
        for op in self.get_tickets_to_print(order):
            multi_pk_pass.add_pkpass(self.generate_pass(op))
        return f"passes_{self.event.slug}_{order.code}.pkpasses", "application/vnd.apple.pkpasses", multi_pk_pass.get_buffer()
