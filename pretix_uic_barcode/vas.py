import base64
import pathlib
import asn1tools
import inspect
import datetime
from django.utils.functional import cached_property
from pretix.base.models import OrderPosition

ROOT = pathlib.Path(__file__).parent
VAS_HEADER = asn1tools.compile_files([ROOT / "asn1" / "vasData.asn"], codec="uper")


class VASDataGenerator:
    def __init__(self, event):
        self.event = event

    @cached_property
    def vas_element_generators(self) -> list:
        from .signals import register_vas_element_generators

        responses = register_vas_element_generators.send(self.event)
        renderers = []
        for receiver, response in responses:
            if not isinstance(response, list):
                response = [response]
            for p in response:
                pp = p(self.event)
                renderers.append(pp)
        return renderers

    def generate_vas_data(self, order_position: OrderPosition = None) -> str:
        vas_elements = []
        for generator in self.vas_element_generators:
            kwargs = {}
            params = inspect.signature(generator.generate_vas_element).parameters
            if "item" in params:
                kwargs["item"] = order_position.item
            if "variation" in params:
                kwargs["variation"] = order_position.variation
            if "subevent" in params:
                kwargs["subevent"] = order_position.subevent
            if "attendee_name" in params:
                kwargs["attendee_name"] = order_position.attendee_name
            if "valid_from" in params:
                kwargs["valid_from"] = order_position.valid_from
            if "valid_until" in params:
                kwargs["valid_until"] = order_position.valid_until
            if "order_datetime" in params:
                kwargs["order_datetime"] = order_position.order.datetime.astimezone(datetime.timezone.utc) if order_position.order.datetime else None
            if "order_position" in params:
                kwargs["order_position"] = order_position
            if "order" in params:
                kwargs["order"] = order_position.order
            if "organizer" in params:
                kwargs["organizer"] = order_position.organizer
            if elm := generator.generate_vas_element(**kwargs):
                vas_elements.append(elm)

        return base64.b85encode(VAS_HEADER.encode("VASData", {
            "data": [{
                "dataFormat": elm.record_id(),
                "data": elm.record_content()
            } for elm in vas_elements],
        })).decode()
