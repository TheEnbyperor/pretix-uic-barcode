import base64
import inspect
import json
import typing
import collections
import urllib

import google.auth.jwt
import googleapiclient.errors
import pytz
import decimal
from django import forms
from django.conf import settings
from django.core.files.storage import default_storage
from django.core.validators import RegexValidator, MinValueValidator
from django.urls import reverse
from django.utils import translation
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _
from pretix.base.i18n import get_language_without_region
from pretix.base.models import Order, OrderPosition, SubEvent
from pretix.base.ticketoutput import BaseTicketOutput
from pretix.multidomain.urlreverse import build_absolute_uri
from urllib.parse import urljoin
from . import gwallet, barcode, models, vas, utils
from .forms import PNGImageField


class GoogleWalletOutput(BaseTicketOutput):
    identifier = "google-wallet-uic"
    verbose_name = _("Google Wallet")
    download_button_icon = "fa-mobile"
    download_button_text = _("Google Wallet")
    multi_download_enabled = True
    preview_allowed = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = gwallet.get_client()
        self.signer = gwallet.get_signer()
        self.event_class = self.client.eventticketclass() if self.client else None
        self.event_object = self.client.eventticketobject() if self.client else None
        self.barcode_generator = barcode.UICBarcodeGenerator(self.event)
        self.vas_generator = vas.VASDataGenerator(self.event)

    @property
    def is_enabled(self):
        if not self.client or not self.signer:
            return False
        return self.settings.get('_enabled', as_type=bool)

    @cached_property
    def module_generators(self) -> list:
        from .signals import generate_google_wallet_module

        responses = generate_google_wallet_module.send(self.event)
        generators = []
        for receiver, response in responses:
            if not isinstance(response, list):
                response = [response]
            for p in response:
                generators.append(p)
        return generators

    @property
    def settings_form_fields(self) -> dict:
        sa_email = self.client._http.credentials.service_account_email if self.client else "N/A"
        return collections.OrderedDict(
            list(super().settings_form_fields.items())
            + [("issuer_id", forms.CharField(
                label=_("Google Issuer ID"),
                required=True,
                help_text=f"The service account {sa_email} must have access to this issuer."
            )), ("logo", PNGImageField(
                label=_("Event logo"),
                required=False,
                image_name="google_wallet_logo.png"
            )), ("hero", PNGImageField(
                label=_("Hero image"),
                required=False,
                image_name="google_wallet_hero.png"
            )), ("bg_color", forms.CharField(
                label=_("Background color"),
                validators=[RegexValidator(regex="^#[0-9a-fA-F]{6}$", message=_(
                    "Please enter the hexadecimal code of a color, e.g. #990000."
                ))],
                required=False,
                widget=forms.TextInput(attrs={
                    "class": "colorpickerfield no-contrast",
                    "placeholder": "#RRGGBB",
                }),
            )), ("rotating_barcodes", forms.BooleanField(
                label=_("Rotating barcodes"),
                required=False,
                help_text=_("Rotating barcodes requires the use of the DOSIPAS barcode format."),
            )), ("rotating_barcode_period", forms.IntegerField(
                label=_("Rotating barcode period (ms)"),
                required=False,
                initial=5000,
                validators=[MinValueValidator(1)],
            ))]
        )

    @staticmethod
    def _public_language_code(lang: str) -> str:
        return translation.get_language_info(lang).get('public_code', lang)

    def _make_localised_string(self, val):
        default_lang = get_language_without_region()

        langs = {}

        if isinstance(val, str):
            langs[self._public_language_code(default_lang)] = val
        elif isinstance(val, list):
            for k, v in val:
                langs[self._public_language_code(k)] = str(v)
        else:
            if default_lang not in langs:
                langs[self._public_language_code(default_lang)] = val.localize(default_lang)
            for k, v in val.data.items():
                langs[self._public_language_code(k)] = str(v)

        values = list(langs.items())

        return {
            "translatedValues": [{
                "language": k,
                "value": v
            } for k, v in values[1:]],
            "defaultValue": {
                "language": values[0][0],
                "value": values[0][1],
            }
        }

    def _generate_class(self, event):
        issuer_id = self.settings.get("issuer_id")
        tz = pytz.timezone(event.settings.timezone)

        if isinstance(event, SubEvent):
            class_id = f"{issuer_id}.pretix.ticket.{event.event.organizer.slug}.{event.event.slug}.{event.pk}"
            tl_event = event.event
            uri = build_absolute_uri(event.event, "presale:event.index", {"subevent": event.pk})
        else:
            class_id = f"{issuer_id}.pretix.ticket.{event.organizer.slug}.{event.slug}"
            tl_event = event
            uri = build_absolute_uri(event, "presale:event.index")

        data = {
            "id": class_id,
            "eventName": self._make_localised_string(event.name),
            "eventId": f"{tl_event.organizer.slug}_{tl_event.slug}",
            "issuerName": str(tl_event.organizer.name),
            "enableSmartTap": True,
            "redemptionIssuers": [
                str(issuer_id)
            ],
            "homepageUri": {
                "uri": uri,
                "localizedDescription": self._make_localised_string(event.name),
            },
            "securityAnimation": {
                "animationType": "FOIL_SHIMMER"
            },
            "reviewStatus": "underReview",
            "confirmationCodeLabel": "ORDER_NUMBER",
            "dateTime": {
                "start": event.date_from.astimezone(tz).isoformat()
            },
            "callbackOptions": {
                "url": utils.idna_encode_url(urllib.parse.urljoin(settings.SITE_URL, reverse("plugins:pretix_uic_barcode:google_wallet_callback", kwargs={
                    "organizer": self.event.organizer.slug,
                    "event": self.event.slug,
                }))),
            }
        }

        if logo_file := self.settings.get("logo", as_type=str, default='')[7:]:
            data["logo"] = {
                "sourceUri": {
                    "uri": urljoin(build_absolute_uri(self.event, 'presale:event.index'), default_storage.url(logo_file))
                }
            }
        if hero_file := self.settings.get("hero", as_type=str, default='')[7:]:
            data["heroImage"] = {
                "sourceUri": {
                    "uri": urljoin(build_absolute_uri(self.event, 'presale:event.index'), default_storage.url(hero_file))
                }
            }
        if bg_color := self.settings.get("bg_color", None):
            data["hexBackgroundColor"] = bg_color

        if event.location:
            data["venue"] = {
                "name": self._make_localised_string([
                    (k, str(v).split("\n")[0].replace("\r", "") or "N/A") for k, v in event.location.data.items()
                ]),
                "address": self._make_localised_string([
                    (k, "\n".join(str(v).split("\n")[1:]).replace("\r", "") or "N/A") for k, v in event.location.data.items()
                ])
            }
        if event.geo_lat and event.geo_lon:
            data["locations"] = [{
                "latitude": float(event.geo_lat),
                "longitude": float(event.geo_lon),
            }]
        if event.date_to:
            data["dateTime"]["end"] = event.date_to.astimezone(tz).isoformat()
        if event.date_admission:
            data["dateTime"]["doorsOpen"] = event.date_admission.astimezone(tz).isoformat()

        return data

    def get_or_update_class(self, event):
        new_class = self._generate_class(event)
        cache_id = f"google_wallet_cached_class_data_{new_class['id']}"
        if prev_class := event.settings.get(cache_id, None):
            prev_class = json.loads(prev_class)
            if new_class != prev_class:
                self.event_class.update(
                    resourceId=new_class["id"],
                    body=new_class
                ).execute()
                event.settings.set(cache_id, json.dumps(new_class))
        else:
            self.event_class.insert(body=new_class).execute()
            event.settings.set(cache_id, json.dumps(new_class))

        return new_class["id"]

    def generate_pass(self, position: OrderPosition, force: bool = True):
        order = position.order
        event = position.subevent or position.order.event
        tz = pytz.timezone(order.event.settings.timezone)

        class_id = self.get_or_update_class(event)
        issuer_id = self.settings.get("issuer_id")
        object_id = f"{issuer_id}.{order.event.organizer.slug}.{position.code}"

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

        object_data = {
            "id": object_id,
            "classId": class_id,
            "ticketNumber": position.code,
            "smartTapRedemptionValue": self.vas_generator.generate_vas_data(position),
            "reservationInfo": {
                "confirmationCode": order.code
            },
            "ticketType": self._make_localised_string([
                (k, f"{v} - {position.variation.value.localize(k)}",)  for k, v in position.item.name.data.items()
            ]) if position.variation else self._make_localised_string(position.item.name),
            "faceValue": {
                "currencyCode": event.currency,
                "micros": int(position.price * decimal.Decimal(1000000))
            },
            "imageModulesData": [],
            "textModulesData": [],
            "valueAddedModuleData": [],
            "messages": [],
        }

        if date_to:
            object_data["validTimeInterval"] = {
                "start": {
                    "date": date_from.isoformat(),
                },
                "end": {
                    "date": date_to.isoformat(),
                }
            }

        if order.status == Order.STATUS_PAID:
            object_data["state"] = "ACTIVE"
        elif order.status == Order.STATUS_EXPIRED:
            object_data["state"] = "EXPIRED"
        else:
            object_data["state"] = "INACTIVE"

        if position.attendee_name:
            object_data["ticketHolderName"] = position.attendee_name

        for g in self.module_generators:
            kwargs = {}
            params = inspect.signature(g).parameters
            if "order_position" in params:
                kwargs["order_position"] = position
            if "order" in params:
                kwargs["order"] = order
            for module_type, module_data in g(**kwargs):
                if module_type == "imageModule":
                    object_data["imageModulesData"].append(module_data)
                elif module_type == "textModule":
                    object_data["textModulesData"].append(module_data)
                elif module_type == "valueAddedModule":
                    object_data["valueAddedModuleData"].append(module_data)
                elif module_type == "message":
                    object_data["messages"].append(module_data)

        if self.event.settings.ticket_secret_generator == "uic-barcodes":
            if self.event.settings.uic_barcode_encoding == "b45":
                op_secret = self.barcode_generator.generate_barcode(position)
                object_data["barcode"] = {
                    "type": "QR_CODE",
                    "value": op_secret.decode("utf-8"),
                    "alternateText": position.secret,
                }
            else:
                if self.settings.get("rotating_barcodes", False, as_type=bool):
                    op_secret_totp = self.barcode_generator.generate_barcode(position, totp=True)
                    period = self.settings.get("rotating_barcode_period", 5000, as_type=int)
                    totp_secret, _ = models.OrderPositionTotp.objects.get_or_create(order_position=position)
                    object_data["rotatingBarcode"] = {
                        "type": "AZTEC",
                        "valuePattern": op_secret_totp.decode("iso-8859-1"),
                        "alternateText": position.secret,
                        "totpDetails": {
                            "periodMillis": period,
                            "algorithm": "TOTP_SHA1",
                            "parameters": {
                                "key": base64.b16encode(totp_secret.totp_key).decode("ascii"),
                                "valueLength": 8
                            }
                        }
                    }

                op_secret = self.barcode_generator.generate_barcode(position)
                object_data["barcode"] = {
                    "type": "AZTEC",
                    "value": op_secret.decode("iso-8859-1"),
                    "alternateText": position.secret,
                }
        else:
            object_data["barcode"] = {
                "type": "QR_CODE",
                "value": position.secret,
                "alternateText": position.secret,
            }

        try:
            self.event_object.get(resourceId=object_id).execute()
        except googleapiclient.errors.HttpError as e:
            if e.status_code != 404:
                raise e
            else:
                if force:
                    self.event_object.insert(body=object_data).execute()
        else:
            self.event_object.update(resourceId=object_id, body=object_data).execute()

        return {
            "id": object_id,
            "classId": class_id,
        }

    def generate(self, position: OrderPosition) -> typing.Tuple[str, str, str]:
        claims = {
            "iss": self.client._http.credentials.service_account_email,
            "aud": "google",
            "typ": "savetowallet",
            "payload": {
                "eventTicketObjects": [self.generate_pass(position)]
            }
        }
        token = google.auth.jwt.encode(self.signer, claims).decode("utf-8")
        url = f"https://pay.google.com/gp/v/save/{token}"
        return "", "text/uri-list", url

    def generate_order(self, order: Order) -> typing.Tuple[str, str, str]:
        claims = {
            "iss": self.client._http.credentials.service_account_email,
            "aud": "google",
            "typ": "savetowallet",
            "payload": {
                "eventTicketObjects": [self.generate_pass(op) for op in self.get_tickets_to_print(order)]
            }
        }
        token = google.auth.jwt.encode(self.signer, claims).decode("utf-8")
        url = f"https://pay.google.com/gp/v/save/{token}"
        return "", "text/uri-list", url
