import inspect
import json
import typing
import collections
import urllib.parse
import pytz
from django import forms
from django.conf import settings
from django.contrib.staticfiles import finders
from django.core.files import File
from django.core.files.storage import default_storage
from django.core.validators import RegexValidator
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _
from pretix.base.models import Order, OrderPosition
from pretix.base.ticketoutput import BaseTicketOutput
from pretix.multidomain.urlreverse import build_absolute_uri
from . import pkpass, barcode, models, vas, utils
from .forms import PNGImageField


class AppleWalletOutput(BaseTicketOutput):
    identifier = "apple-wallet-uic"
    verbose_name = _("Apple Wallet")
    download_button_icon = "fa-mobile"
    download_button_text = _("Apple Wallet")
    multi_download_enabled = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.signer = pkpass.get_signer()
        self.barcode_generator = barcode.UICBarcodeGenerator(self.event)
        self.vas_generator = vas.VASDataGenerator(self.event)

    @property
    def is_enabled(self):
        if not self.signer:
            return False
        return self.settings.get('_enabled', as_type=bool)

    @cached_property
    def module_generators(self) -> list:
        from .signals import generate_apple_wallet_module

        responses = generate_apple_wallet_module.send(self.event)
        generators = []
        for receiver, response in responses:
            if not isinstance(response, list):
                response = [response]
            for p in response:
                generators.append(p)
        return generators

    @property
    def settings_form_fields(self) -> dict:
        return collections.OrderedDict(
            list(super().settings_form_fields.items())
            + [("icon", PNGImageField(
                label=_("Event icon @ 1x"),
                help_text="29x29px PNG image",
                required=False,
                image_name="apple_wallet_icon.png"
            )), ("icon2x", PNGImageField(
                label=_("Event icon @ 2x"),
                help_text="58x58px PNG image",
                required=False,
                image_name="apple_wallet_icon@2x.png"
            )), ("icon3x", PNGImageField(
                label=_("Event icon @ 3x"),
                help_text="87x87px PNG image",
                required=False,
                image_name="apple_wallet_icon@3x.png"
            )), ("logo", PNGImageField(
                label=_("Event logo @ 1x"),
                help_text="160x50px PNG image. The allotted space is 160 x 50 points; in most cases it should be narrower.",
                required=False,
                image_name="apple_wallet_logo.png"
            )), ("logo2x", PNGImageField(
                label=_("Event logo @ 2x"),
                help_text="320x100px PNG image. The allotted space is 160 x 50 points; in most cases it should be narrower.",
                required=False,
                image_name="apple_wallet_logo@2x.png"
            )), ("logo3x", PNGImageField(
                label=_("Event logo @ 3x"),
                help_text="480x150px PNG image. The allotted space is 160 x 50 points; in most cases it should be narrower.",
                required=False,
                image_name="apple_wallet_icon@3x.png"
            )), ("strip", PNGImageField(
                label=_("Strip image @ 1x"),
                help_text="375x98px PNG image",
                required=False,
                image_name="apple_wallet_strip.png"
            )), ("strip2x", PNGImageField(
                label=_("Strip image @ 2x"),
                help_text="750x196px PNG image",
                required=False,
                image_name="apple_wallet_strip@2x.png"
            )), ("strip3x", PNGImageField(
                label=_("Strip image @ 3x"),
                help_text="1125x294px PNG image",
                required=False,
                image_name="apple_wallet_strip@3x.png"
            )), ("thumbnail", PNGImageField(
                label=_("Thumbnail @ 1x"),
                help_text="90x90px PNG image",
                required=False,
                image_name="apple_wallet_thumbnail.png"
            )), ("thumbnail2x", PNGImageField(
                label=_("Thumbnail @ 2x"),
                help_text="180x180px PNG image",
                required=False,
                image_name="apple_wallet_thumbnail@2x.png"
            )), ("thumbnail3x", PNGImageField(
                label=_("Thumbnail @ 3x"),
                help_text="270x270px PNG image",
                required=False,
                image_name="apple_wallet_thumbnail@3x.png"
            )), ("background", PNGImageField(
                label=_("Background image @ 1x"),
                help_text="180x220px PNG image",
                required=False,
                image_name="apple_wallet_background.png"
            )), ("background2x", PNGImageField(
                label=_("Background image @ 2x"),
                help_text="360x440px PNG image",
                required=False,
                image_name="apple_wallet_background@2x.png"
            )), ("background3x", PNGImageField(
                label=_("Background image @ 3x"),
                help_text="540x660px PNG image",
                required=False,
                image_name="apple_wallet_background@3x.png"
            )), ("bg_color", forms.CharField(
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

    def generate_pass(self, position: OrderPosition) -> pkpass.PKPass:
        pk_pass = pkpass.PKPass()
        order = position.order
        event = position.subevent or position.order.event
        tz = pytz.timezone(order.event.settings.timezone)

        pass_serial = f"{order.event.organizer.slug}-{position.code}"
        pass_json = {
            "formatVersion": 1,
            "organizationName": str(event.organizer.name),
            "passTypeIdentifier": self.signer.pass_type_id,
            "teamIdentifier": self.signer.team_id,
            "serialNumber": pass_serial,
            "groupingIdentifier": f"{order.event.organizer.slug}-{order.code}",
            "description": str(event.name),
            "suppressStripShine": True,
            "suppressHeaderDarkening": True,
            "locations": [],
            "webServiceURL": utils.idna_encode_url(urllib.parse.urljoin(settings.SITE_URL, "/api/apple_wallet")),
            "authenticationToken": position.web_secret,
            "eventTicket": {
                "headerFields": [],
                "primaryFields": [],
                "secondaryFields": [],
                "auxiliaryFields": [],
                "backFields": []
            },
            "barcodes": [],
            "relevantDates": [],
            "voided": order.status != Order.STATUS_PAID,
        }

        if self.event.settings.ticket_secret_generator == "uic-barcodes":
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
        else:
            pass_json["barcodes"].append({
                "format": "PKBarcodeFormatQR",
                "message": position.secret,
                "messageEncoding": "utf-8",
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
        date_admission = event.date_admission.astimezone(tz) if event.date_admission else None

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
            pass_json["relevantDates"].append({
                "startDate": date_admission.isoformat() if date_admission else date_from.isoformat(),
                "endDate": date_to.isoformat(),
            })
            if position.item.admission:
                pass_json["eventTicket"]["auxiliaryFields"].append({
                    "key": "ev-to",
                    "label": "To",
                    "dateStyle": "PKDateStyleMedium",
                    "timeStyle": "PKDateStyleShort",
                    "value": date_to.isoformat(),
                    "ignoresTimeZone": True
                })
        else:
            pass_json["relevantDates"].append({
                "date": date_admission.isoformat() if date_admission else date_from.isoformat(),
            })

        if position.item.admission and event.date_admission:
            pass_json["eventTicket"]["headerFields"].append({
                "key": "ev-admission",
                "label": "Admission",
                "dateStyle": "PKDateStyleMedium",
                "timeStyle": "PKDateStyleShort",
                "value": event.date_admission.astimezone(tz).isoformat(),
                "ignoresTimeZone": True,
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
            "value": event_url,
            "attributedValue": f"<a href=\"{event_url}\">{event_url.replace('https://', '')}</a>",
        })

        if bg_color := self.settings.get("bg_color", None):
            pass_json["backgroundColor"] = bg_color
        if fg_color := self.settings.get("fg_color", None):
            pass_json["foregroundColor"] = fg_color
        if label_color := self.settings.get("label_color", None):
            pass_json["labelColor"] = label_color

        if icon_file := self.settings.get("icon", None, as_type=File):
            pk_pass.add_file("icon.png", default_storage.open(icon_file.name, "rb").read())
            if icon_2x_file := self.settings.get("icon2x", None, as_type=File):
                pk_pass.add_file("icon@2x.png", default_storage.open(icon_2x_file.name, "rb").read())
            if icon_3x_file := self.settings.get("icon3x", None, as_type=File):
                pk_pass.add_file("icon@3x.png", default_storage.open(icon_3x_file.name, "rb").read())
        else:
            pk_pass.add_file("icon.png", open(finders.find("pretix_uic_barcode/icon.png"), "rb").read())

        if logo_file := self.settings.get("logo", None, as_type=File):
            pk_pass.add_file("logo.png", default_storage.open(logo_file.name, "rb").read())
        if logo_2x_file := self.settings.get("logo2x", None, as_type=File):
            pk_pass.add_file("logo@2x.png", default_storage.open(logo_2x_file.name, "rb").read())
        if logo_3x_file := self.settings.get("logo3x", None, as_type=File):
            pk_pass.add_file("logo@3x.png", default_storage.open(logo_3x_file.name, "rb").read())

        if strip_file := self.settings.get("strip", None, as_type=File):
            pk_pass.add_file("strip.png", default_storage.open(strip_file.name, "rb").read())
        if strip_2x_file := self.settings.get("strip2x", None, as_type=File):
            pk_pass.add_file("strip@2x.png", default_storage.open(strip_2x_file.name, "rb").read())
        if strip_3x_file := self.settings.get("strip3x", None, as_type=File):
            pk_pass.add_file("strip@3x.png", default_storage.open(strip_3x_file.name, "rb").read())

        if thumbnail_file := self.settings.get("thumbnail", None, as_type=File):
            pk_pass.add_file("thumbnail.png", default_storage.open(thumbnail_file.name, "rb").read())
        if thumbnail_2x_file := self.settings.get("thumbnail2x", None, as_type=File):
            pk_pass.add_file("thumbnail@2x.png", default_storage.open(thumbnail_2x_file.name, "rb").read())
        if thumbnail_3x_file := self.settings.get("thumbnail3x", None, as_type=File):
            pk_pass.add_file("thumbnail@3x.png", default_storage.open(thumbnail_3x_file.name, "rb").read())

        if background_file := self.settings.get("background", None, as_type=File):
            pk_pass.add_file("background.png", default_storage.open(background_file.name, "rb").read())
        if background_2x_file := self.settings.get("background2x", None, as_type=File):
            pk_pass.add_file("background@2x.png", default_storage.open(background_2x_file.name, "rb").read())
        if background_3x_file := self.settings.get("background3x", None, as_type=File):
            pk_pass.add_file("background@3x.png", default_storage.open(background_3x_file.name, "rb").read())

        for g in self.module_generators:
            kwargs = {}
            params = inspect.signature(g).parameters
            if "order_position" in params:
                kwargs["order_position"] = position
            if "order" in params:
                kwargs["order"] = order
            for module_type, module_data in g(**kwargs):
                if module_type == "primaryField":
                    pass_json["eventTicket"]["primaryFields"].append(module_data)
                elif module_type == "secondaryField":
                    pass_json["eventTicket"]["secondaryFields"].append(module_data)
                elif module_type == "auxiliaryField":
                    pass_json["eventTicket"]["auxiliaryFields"].append(module_data)
                elif module_type == "headerField":
                    pass_json["eventTicket"]["headerFields"].append(module_data)
                elif module_type == "backField":
                    pass_json["eventTicket"]["backFields"].append(module_data)

        pk_pass.add_file("pass.json", json.dumps(pass_json).encode("utf-8"))

        contents_hash = pk_pass.contents_hash()
        last_update, created = models.AppleWalletPass.objects.get_or_create(
            order_position=position,
            defaults={
                "pass_type_id": self.signer.pass_type_id,
                "pass_serial": pass_serial,
                "last_modified": timezone.now(),
                "contents_hash": contents_hash,
            }
        )
        if not created and last_update.contents_hash != contents_hash:
            last_update.contents_hash = contents_hash
            last_update.last_modified = timezone.now()
            last_update.save()

        pk_pass.sign(self.signer)
        return pk_pass

    def generate(self, position: OrderPosition) -> typing.Tuple[str, str, bytes]:
        pk_pass = self.generate_pass(position)
        return f"pass_{self.event.slug}_{position.order.code}.pkpass", "application/vnd.apple.pkpass", pk_pass.get_buffer()

    def generate_order(self, order: Order) -> typing.Tuple[str, str, bytes]:
        multi_pk_pass = pkpass.MultiPKPass()
        for op in self.get_tickets_to_print(order):
            multi_pk_pass.add_pkpass(self.generate_pass(op))
        return f"passes_{self.event.slug}_{order.code}.pkpasses", "application/vnd.apple.pkpasses", multi_pk_pass.get_buffer()
