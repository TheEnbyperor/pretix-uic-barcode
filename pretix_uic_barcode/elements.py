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


class VASElement(abc.ABC):
    @abc.abstractmethod
    def record_id(self) -> typing.Optional[str]:
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


class PretixDataVASElement(VASElement):
    def __init__(self, data: typing.Dict):
        self.data = data

    def record_id(self):
        return "P"

    def record_content(self) -> bytes:
        return BARCODE_CONTENT.encode("VASPretixTicket", self.data)


class BaseBarcodeElementGenerator(abc.ABC):
    def __init__(self, event):
        self.event = event

    @abc.abstractmethod
    def generate_element(self, **kwargs) -> typing.Optional[UICBarcodeElement]:
        raise NotImplementedError()


class BaseVASElementGenerator(abc.ABC):
    def __init__(self, event):
        self.event = event

    @abc.abstractmethod
    def generate_vas_element(self, **kwargs) -> typing.Optional[VASElement]:
        raise NotImplementedError()


class PretixDataBarcodeElementGenerator(BaseBarcodeElementGenerator, BaseVASElementGenerator):
    @staticmethod
    def map_timestamp(timestamp):
        timestamp_utc = timestamp.timetuple()
        return timestamp_utc.tm_year, timestamp_utc.tm_yday, (60 * timestamp_utc.tm_hour) + timestamp_utc.tm_min

    def generate_element(
            self, item: Item, order_datetime: datetime.datetime,
            order_position: OrderPosition,
            variation: ItemVariation = None, subevent: SubEvent = None,
            attendee_name: str = None, valid_from: datetime.datetime = None, valid_until: datetime.datetime = None,
            has_totp: bool = False,
    ) -> PretixDataBarcodeElement:
        valid_from = self.map_timestamp(valid_from) if valid_from else None
        valid_until = self.map_timestamp(valid_until) if valid_until else None
        order_datetime = self.map_timestamp(order_datetime)

        ticket_data = {
            "uniqueId": order_position.secret,
            "eventSlug": self.event.slug,
            "itemId": item.pk,
            "orderYear": order_datetime[0],
            "orderDay": order_datetime[1],
            "orderTime": order_datetime[2],
            "hasTotp": has_totp,
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

    def generate_vas_element(
            self, item: Item, order_position: OrderPosition,
            variation: ItemVariation = None, subevent: SubEvent = None,
            valid_from: datetime.datetime = None, valid_until: datetime.datetime = None,
    ) -> PretixDataVASElement:
        valid_from = self.map_timestamp(valid_from) if valid_from else None
        valid_until = self.map_timestamp(valid_until) if valid_until else None

        ticket_data = {
            "uniqueId": order_position.secret,
            "eventSlug": self.event.slug,
            "itemId": item.pk,
        }
        if variation:
            ticket_data["variationId"] = variation.pk
        if subevent:
            ticket_data["subeventId"] = subevent.pk
        if valid_from:
            ticket_data["validFromYear"] = valid_from[0]
            ticket_data["validFromDay"] = valid_from[1]
            ticket_data["validFromTime"] = valid_from[2]
        if valid_until:
            ticket_data["validUntilYear"] = valid_until[0]
            ticket_data["validUntilDay"] = valid_until[1]
            ticket_data["validUntilTime"] = valid_until[2]

        return PretixDataVASElement(ticket_data)
