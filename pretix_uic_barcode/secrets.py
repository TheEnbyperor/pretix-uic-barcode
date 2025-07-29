import datetime
import base45
import asn1tools
import inspect
from django.utils.functional import cached_property
from pretix.base.secrets import BaseTicketSecretGenerator, ParsedSecret
from pretix.base.models import Item, ItemVariation, SubEvent, OrderPosition, Order, Organizer
from . import barcode


class UICSecretGenerator(BaseTicketSecretGenerator):
    verbose_name = "UIC barcodes"
    identifier = "uic-barcodes"
    use_revocation_list = True

    def __init__(self, event):
        super().__init__(event)
        self.gen = barcode.UICBarcodeGenerator(event)

    @cached_property
    def barcode_element_generators(self) -> list:
        from .signals import register_barcode_element_generators

        responses = register_barcode_element_generators.send(self.event)
        renderers = []
        for receiver, response in responses:
            if not isinstance(response, list):
                response = [response]
            for p in response:
                pp = p(self.event)
                renderers.append(pp)
        return renderers

    def parse_secret(self, secret: str):
        if data := self.gen.parse(secret):
            if data["eventSlug"] != self.event.slug:
                return None
            item = self.event.items.filter(pk=data["itemId"]).first()
            subevent = self.event.subevents.filter(pk=data["subeventId"]).first() if "subeventId" in data else None
            variation = item.variations.filter(pk=data["variationId"]).first() if "variationId" in data else None
            return ParsedSecret(
                item=item,
                subevent=subevent,
                variation=variation,
                attendee_name=data["attendeeName"],
                opaque_id=data["uniqueId"].hex()
            )
        return None

    def generate_secret(
            self, item: Item, variation: ItemVariation = None,
            subevent: SubEvent = None, attendee_name: str = None,
            valid_from: datetime.datetime = None,
            valid_until: datetime.datetime = None,
            order_datetime: datetime.datetime = None,
            order_position: OrderPosition = None,
            order: Order = None,
            organizer: Organizer = None,
            current_secret: str = None,
            force_invalidate=False
    ) -> str:
        if valid_from:
            valid_from = valid_from.astimezone(datetime.timezone.utc)
            valid_from_tt = valid_from.timetuple()
            valid_from_uic = (valid_from_tt.tm_year, valid_from_tt.tm_yday,
                          (60 * valid_from_tt.tm_hour) + valid_from_tt.tm_min)
        else:
            valid_from = None
            valid_from_uic = None
        if valid_until:
            valid_until = valid_until.astimezone(datetime.timezone.utc)
            valid_until_tt = valid_until.timetuple()
            valid_until_uic = (valid_until_tt.tm_year, valid_until_tt.tm_yday,
                           (60 * valid_until_tt.tm_hour) + valid_until_tt.tm_min)
        else:
            valid_until = None
            valid_until_uic = None

        if current_secret and not force_invalidate:
            if current_data := self._parse(current_secret):
                if current_data["eventSlug"] == self.event.slug and \
                        current_data["itemId"] == item.pk and \
                        current_data.get("variationId") == (variation.pk if variation else None) and \
                        current_data.get("subeventId") == (subevent.pk if subevent else None) and \
                        current_data.get("validFromYear") == (valid_from_uic[0] if valid_from_uic else None) and \
                        current_data.get("validFromDay") == (valid_from_uic[1] if valid_from_uic else None) and \
                        current_data.get("validFromTime") == (valid_from_uic[1] if valid_from_uic else None) and \
                        current_data.get("validUntilYear") == (valid_until_uic[0] if valid_until_uic else None) and \
                        current_data.get("validUntilDay") == (valid_until_uic[1] if valid_until_uic else None) and \
                        current_data.get("validUntilTime") == (valid_until_uic[1] if valid_until_uic else None):
                    return current_secret

        barcode_elements = []
        for generator in self.barcode_element_generators:
            kwargs = {}
            params = inspect.signature(generator.generate_element).parameters
            if "item" in params:
                kwargs["item"] = item
            if "variation" in params:
                kwargs["variation"] = variation
            if "subevent" in params:
                kwargs["subevent"] = subevent
            if "attendee_name" in params:
                kwargs["attendee_name"] = attendee_name
            if "valid_from" in params:
                kwargs["valid_from"] = valid_from
            if "valid_until" in params:
                kwargs["valid_until"] = valid_until
            if "order_datetime" in params:
                kwargs["order_datetime"] = order_datetime.astimezone(datetime.timezone.utc) if order_datetime else None
            if "order_position" in params:
                kwargs["order_position"] = order_position
            if "order" in params:
                kwargs["order"] = order
            if "organizer" in params:
                kwargs["organizer"] = organizer
            if elm := generator.generate_element(**kwargs):
                barcode_elements.append(elm)

        return self.gen.generate(barcode_elements)
