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


class RawOutput(BaseTicketOutput):
    identifier = "raw-uic"
    verbose_name = _("Raw Barcode")
    multi_download_enabled = False
    preview_allowed = False
    is_enabled = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.barcode_generator = barcode.UICBarcodeGenerator(self.event)

    def generate(self, position: OrderPosition) -> typing.Tuple[str, str, bytes]:
        code = self.barcode_generator.generate_barcode(position)

        output = json.dumps({
            "encoding": self.event.settings.uic_barcode_encoding,
            "code": base64.b64encode(code).decode(),
        })

        return "", "application/json", output.encode()

    def generate_order(self, order: Order) -> typing.Tuple[str, str, bytes]:
        raise NotImplementedError()
