import datetime
import asn1tools
import abc
import pathlib
import typing
from pretix.base.models import Item, ItemVariation, SubEvent, OrderPosition

ROOT = pathlib.Path(__file__).parent
BARCODE_CONTENT = asn1tools.compile_files([ROOT / "asn1" / "uicPretix.asn"], codec="uper")


class UICBarcodeElement(abc.ABC):
    @abc.abstractmethod
    def tlb_record_id(self) -> typing.Optional[str]:
        raise NotImplementedError()

    @staticmethod
    def tlb_record_version() -> int:
        return 1

    @abc.abstractmethod
    def dosipas_record_id(self) -> typing.Optional[str]:
        raise NotImplementedError()

    @abc.abstractmethod
    def record_content(self) -> bytes:
        raise NotImplementedError()


class PretixDataBarcodeElement(UICBarcodeElement):
    def __init__(self, data: typing.Dict):
        self.data = data

    def tlb_record_id(self):
        return "5101PX"

    def dosipas_record_id(self):
        return "_5101PTIX"

    def record_content(self) -> bytes:
        return BARCODE_CONTENT.encode("PretixTicket", self.data)


class BaseBarcodeElementGenerator:
    def __init__(self, event):
        self.event = event

    def generate_element(self, **kwargs) -> typing.Optional[UICBarcodeElement]:
        raise NotImplementedError()


class PretixDataBarcodeElementGenerator(BaseBarcodeElementGenerator):
    def generate_element(
            self, item: Item, order_datetime: datetime.datetime,
            order_position: OrderPosition,
            variation: ItemVariation = None, subevent: SubEvent = None,
            attendee_name: str = None, valid_from: datetime.datetime = None, valid_until: datetime.datetime = None,
    ) -> PretixDataBarcodeElement:
        if valid_from:
            valid_from_utc = valid_from.timetuple()
            valid_from = (valid_from_utc.tm_year, valid_from_utc.tm_yday,
                          (60 * valid_from_utc.tm_hour) + valid_from_utc.tm_min)
        if valid_until:
            valid_until_utc = valid_until.timetuple()
            valid_until = (valid_until_utc.tm_year, valid_until_utc.tm_yday,
                           (60 * valid_until_utc.tm_hour) + valid_until_utc.tm_min)

        order_datetime_utc = order_datetime.timetuple()
        order_datetime = (order_datetime_utc.tm_year, order_datetime_utc.tm_yday,
                       (60 * order_datetime_utc.tm_hour) + order_datetime_utc.tm_min)

        ticket_data = {
            "uniqueId": order_position.secret,
            "eventSlug": self.event.slug,
            "itemId": item.pk,
            "orderYear": order_datetime[0],
            "orderDay": order_datetime[1],
            "orderTime": order_datetime[2],
        }
        if variation:
            ticket_data["variationId"] = variation.pk
        if subevent:
            ticket_data["subeventId"] = subevent.pk
        if attendee_name:
            ticket_data["attendeeName"] = attendee_name
        if valid_from:
            ticket_data["validFromYear"] = valid_from[0]
            ticket_data["validFromDay"] = valid_from[1]
            ticket_data["validFromTime"] = valid_from[2]
        if valid_until:
            ticket_data["validUntilYear"] = valid_until[0]
            ticket_data["validUntilDay"] = valid_until[1]
            ticket_data["validUntilTime"] = valid_until[2]

        return PretixDataBarcodeElement(ticket_data)
