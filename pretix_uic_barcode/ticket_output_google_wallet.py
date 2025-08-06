import json
import typing
import collections
import google.auth.jwt
import googleapiclient.errors
import pytz
import decimal
from django import forms
from django.conf import settings
from django.utils import translation
from django.utils.translation import gettext_lazy as _
from pretix.base.models import Order, OrderPosition, SubEvent
from pretix.base.ticketoutput import BaseTicketOutput
from pretix.multidomain.urlreverse import build_absolute_uri
from . import gwallet, barcode


class GoogleWalletOutput(BaseTicketOutput):
    identifier = "google-wallet-uic"
    verbose_name = "Google Wallet"
    download_button_icon = "fa-mobile"
    download_button_text = _("Google Wallet")
    multi_download_enabled = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = gwallet.get_client()
        self.signer = gwallet.get_signer()
        self.event_class = self.client.eventticketclass() if self.client else None
        self.event_object = self.client.eventticketobject() if self.client else None
        self.barcode_generator = barcode.UICBarcodeGenerator(self.event)

    @property
    def settings_form_fields(self) -> dict:
        return collections.OrderedDict(
            list(super().settings_form_fields.items())
            + [("issuer_id", forms.CharField(
                label=_("Google Issuer ID"),
                required=True,
            ))]
        )

    @staticmethod
    def _make_localised_string(val):
        default_lang = translation.get_language() or settings.LANGUAGE_CODE

        if isinstance(val, str):
            return {
                "defaultValue": {
                    "language": default_lang,
                    "value": val,
                }
            }

        return {
            "translatedValues": [{
                "language": k,
                "value": str(v)
            } for k, v in val.data.items()],
            "defaultValue": {
                "language": default_lang,
                "value": val.localize(default_lang),
            }
        }

    def _generate_class(self, event):
        issuer_id = self.settings.get("issuer_id")

        if isinstance(event, SubEvent):
            class_id = f"{issuer_id}.pretix.ticket.{event.event.organizer.slug}.{event.event.slug}.{event.pk}"
            tl_event = event.event
            uri = build_absolute_uri(event.event, "presale:event.index", {"subevent": event.pk})
        else:
            class_id = f"{issuer_id}.pretix.ticket.{event.organizer.slug}.{event.slug}"
            tl_event = event
            uri = build_absolute_uri(event, "presale:event.index")

        return {
            "id": class_id,
            "eventName": self._make_localised_string(event.name),
            "eventId": f"{tl_event.organizer.slug}_{tl_event.slug}",
            "issuerName": str(tl_event.organizer.name),
            "enableSmartTap": True,
            "homepageUri": {
                "uri": uri
            },
            "securityAnimation": {
                "animationType": "FOIL_SHIMMER"
            },
            "reviewStatus": "underReview",
            "confirmationCodeLabel": "ORDER_NUMBER"
        }

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
                event.settings.save()
        else:
            self.event_class.insert(body=new_class).execute()
            event.settings.set(cache_id, json.dumps(new_class))
            event.settings.save()

        return new_class["id"]

    def _generate_pass(self, position: OrderPosition):
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
            "smartTapRedemptionValue": position.secret,
            "reservationInfo": {
                "confirmationCode": order.code
            },
            "ticketType": self._make_localised_string(position.item.name),
            "faceValue": {
                "currencyCode": event.currency,
                "micros": int(position.price * decimal.Decimal(1000000))
            },
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

        op_secret = self.barcode_generator.generate_barcode(position)
        if self.event.settings.uic_barcode_encoding == "b45":
            object_data["barcode"] = {
                "type": "QR",
                "value": op_secret.decode("utf-8"),
                "alternateText": position.secret,
            }
        else:
            object_data["barcode"] = {
                "type": "AZTEC",
                "value": op_secret.decode("iso-8859-1"),
                "alternateText": position.secret,
            }

        if event.geo_lat and event.geo_lon:
            object_data["locations"] = [{
                "latitude": float(event.geo_lat),
                "longitude": float(event.geo_lon),
            }]

        try:
            self.event_object.get(resourceId=object_id).execute()
        except googleapiclient.errors.HttpError as e:
            if e.status_code != 404:
                raise e
            else:
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
                "eventTicketObjects": [self._generate_pass(position)]
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
                "eventTicketObjects": [self._generate_pass(op) for op in self.get_tickets_to_print(order)]
            }
        }
        token = google.auth.jwt.encode(self.signer, claims).decode("utf-8")
        url = f"https://pay.google.com/gp/v/save/{token}"
        return "", "text/uri-list", url
