import datetime
import pathlib
import base64
import binascii
import zlib
import ber_tlv.tlv
import base45
import asn1tools
from django.utils.functional import cached_property
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pretix.base.secrets import BaseTicketSecretGenerator, ParsedSecret
from pretix.base.models import Item, ItemVariation, SubEvent
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from . import elements

ROOT = pathlib.Path(__file__).parent
BARCODE_HEADER = asn1tools.compile_files([ROOT / "asn1" / "uicBarcodeHeader_v2.0.1.asn"], codec="uper")


class UICSecretGenerator(BaseTicketSecretGenerator):
    verbose_name = "UIC barcodes"
    identifier = "uic-barcodes"
    use_revocation_list = True

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

    def _get_priv_key(self):
        return load_pem_private_key(self.event.settings.uic_barcode_private_key.encode(), None)

    def _parse(self, secret: str):
        pub_key = self._get_priv_key().public_key()

        if self.event.settings.uic_barcode_format == "raw":
            try:
                barcode_bytes = base64.b64decode(secret)
            except binascii.Error:
                return None
        elif self.event.settings.uic_barcode_format == "b45":
            if not secret.startswith("UIC:B45:"):
                return None
            secret = secret[len("UIC:B45:"):]
            try:
                barcode_bytes = base45.b45decode(secret)
            except ValueError:
                return None
        else:
            return None

        try:
            if barcode_bytes.startswith(b"#UT"):
                assert isinstance(pub_key, DSAPublicKey)

                if barcode_bytes[3:5] != b"02":
                    return None
                if int(barcode_bytes[5:9].decode("ascii"), 10) != int(
                        self.event.settings.uic_barcode_security_provider_rics, 10):
                    return None
                if barcode_bytes[9:14].decode("ascii").strip() != self.event.settings.uic_barcode_key_id:
                    return None

                signature, barcode_bytes = barcode_bytes[14:78], barcode_bytes[78:]
                data_len = int(barcode_bytes[0:4].decode("ascii"), 10)
                signed_data = barcode_bytes[4:4 + data_len]

                r, s = signature[0:32], signature[32:64]

                r = r.lstrip(b"\x00")
                s = s.lstrip(b"\x00")

                sig = bytearray([0x30, len(r) + len(s) + 4])
                if r[0] & 0x80:
                    sig[1] += 1
                    sig.extend([0x02, len(r) + 1, 0x00])
                else:
                    sig.extend([0x02, len(r)])
                sig.extend(r)
                if s[0] & 0x80:
                    sig[1] += 1
                    sig.extend([0x02, len(s) + 1, 0x00])
                else:
                    sig.extend([0x02, len(s)])
                sig.extend(s)
                sig = bytes(sig)

                pub_key.verify(sig, signed_data, hashes.SHA256())

                barcode_contents = zlib.decompress(signed_data)

                offset = 0
                records = []
                while barcode_contents[offset:]:
                    record_id = barcode_contents[offset:offset + 6].decode("ascii")
                    record_version = int(barcode_contents[offset + 6:offset + 8].decode("ascii"), 10)
                    record_data_len = int(barcode_contents[offset + 8:offset + 12].decode("ascii"), 10)
                    record_data = barcode_contents[offset + 12:offset + record_data_len]
                    offset += record_data_len + 12
                    records.append((record_id, record_version, record_data))

                ptix_record = next(filter(lambda v: v[0] == "5101PX", records))
                if not ptix_record:
                    return None
                if ptix_record[1] != 1:
                    return None

                ticket_data = elements.BARCODE_CONTENT.decode("PretixTicket", ptix_record[2])
                return ticket_data
            else:
                barcode_data = BARCODE_HEADER.decode("UicBarcodeHeader", barcode_bytes)
                if barcode_data["format"] != "U2":
                    return None

                if self.event.settings.uic_barcode_security_provider_rics and \
                        barcode_data["level2SignedData"]["level1Data"]["securityProviderNum"] != int(
                    self.event.settings.uic_barcode_security_provider_rics, 10):
                    return None
                if self.event.settings.uic_barcode_security_provider_ia5 and \
                        barcode_data["level2SignedData"]["level1Data"][
                            "securityProviderIA5"] != self.event.settings.uic_barcode_security_provider_ia5:
                    return None
                if barcode_data["level2SignedData"]["level1Data"]["keyId"] != int(
                        self.event.settings.uic_barcode_key_id, 10):
                    return None

                tbs_bytes = BARCODE_HEADER.encode("Level1DataType", barcode_data["level2SignedData"]["level1Data"])
                if isinstance(pub_key, DSAPublicKey):
                    pub_key.verify(barcode_data["level2SignedData"]["level1Signature"], tbs_bytes, hashes.SHA256())
                elif isinstance(pub_key, EllipticCurvePublicKey):
                    pub_key.verify(barcode_data["level2SignedData"]["level1Signature"], tbs_bytes,
                                   ECDSA(hashes.SHA256()))
                elif isinstance(pub_key, Ed25519PublicKey):
                    pub_key.verify(barcode_data["level2SignedData"]["level1Signature"], tbs_bytes)
                else:
                    raise NotImplementedError()

                ptix_record = next(filter(
                    lambda v: v["dataFormat"] == "_5101PTIX",
                    barcode_data["level2SignedData"]["level1Data"]["dataSequence"]
                ))
                if not ptix_record:
                    return None

                ticket_data = elements.BARCODE_CONTENT.decode("PretixTicket", ptix_record["data"])
                return ticket_data
        except:
            return None

    def parse_secret(self, secret: str):
        if data := self._parse(secret):
            if data["eventId"] != self.event.pk:
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
            current_secret: str = None,
            force_invalidate=False
    ) -> str:
        if valid_from:
            valid_from_utc = valid_from.astimezone(datetime.timezone.utc).timetuple()
            valid_from = (valid_from_utc.tm_year, valid_from_utc.tm_yday,
                          (60 * valid_from_utc.tm_hour) + valid_from_utc.tm_min)
        if valid_until:
            valid_until_utc = valid_until.astimezone(datetime.timezone.utc).timetuple()
            valid_until = (valid_until_utc.tm_year, valid_until_utc.tm_yday,
                           (60 * valid_until_utc.tm_hour) + valid_until_utc.tm_min)

        if current_secret and not force_invalidate:
            if current_data := self._parse(current_secret):
                if current_data["eventId"] == self.event.pk and \
                        current_data["itemId"] == item.pk and \
                        current_data.get("variationId") == (variation.pk if variation else None) and \
                        current_data.get("subeventId") == (subevent.pk if subevent else None) and \
                        current_data.get("validFromYear") == (valid_from[0] if valid_from else None) and \
                        current_data.get("validFromDay") == (valid_from[1] if valid_from else None) and \
                        current_data.get("validFromTime") == (valid_from[1] if valid_from else None) and \
                        current_data.get("validUntilYear") == (valid_until[0] if valid_until else None) and \
                        current_data.get("validUntilDay") == (valid_until[1] if valid_until else None) and \
                        current_data.get("validUntilTime") == (valid_until[1] if valid_until else None):
                    return current_secret

        barcode_elements = []
        for generator in self.barcode_element_generators:
            if elm := generator.generate_element(
                    item=item, variation=variation, subevent=subevent,
                    attendee_name=attendee_name, valid_from=valid_from, valid_until=valid_until,
                    order_datetime=order_datetime,
            ):
                barcode_elements.append(elm)

        priv_key = self._get_priv_key()
        if self.event.settings.uic_barcode_format == "dosipas":
            if isinstance(priv_key, DSAPrivateKey):
                key_alg = "1.2.840.10040.4.1"
                signing_alg = "2.16.840.1.101.3.4.3.2"
            elif isinstance(priv_key, EllipticCurvePrivateKey):
                curve_name = priv_key.curve.name
                if curve_name == "secp192r1":
                    key_alg = "1.2.840.10045.3.1.1"
                elif curve_name == "secp256r1":
                    key_alg = "1.2.840.10045.3.1.7"
                elif curve_name == "secp256k1":
                    key_alg = "1.3.132.0.10"
                elif curve_name == "secp224r1":
                    key_alg = "1.3.132.0.33"
                elif curve_name == "secp384r1":
                    key_alg = "1.3.132.0.34"
                elif curve_name == "secp521r1":
                    key_alg = "1.3.132.0.35"
                else:
                    key_alg = None
                signing_alg = "1.2.840.10045.4.3.2"
            elif isinstance(priv_key, Ed25519PrivateKey):
                key_alg = "1.3.101.112"
                signing_alg = "1.3.101.112"
            else:
                key_alg = None
                signing_alg = None

            barcode_data = {
                "format": "U2",
                "level2SignedData": {
                    "level1Data": {
                        "keyId": int(self.event.settings.uic_barcode_key_id, 10),
                        "level1KeyAlg": key_alg,
                        "level1SigningAlg": signing_alg,
                        "dataSequence": []
                    },
                    "level1Signature": b"",
                },
            }

            if self.event.settings.uic_barcode_security_provider_rics:
                barcode_data["level2SignedData"]["level1Data"]["securityProviderNum"] = \
                    int(self.event.settings.uic_barcode_security_provider_rics, 10)
            elif self.event.settings.uic_barcode_security_provider_ia5:
                barcode_data["level2SignedData"]["level1Data"]["securityProviderIA5"] = \
                    self.event.settings.uic_barcode_security_provider_ia5

            for elm in barcode_elements:
                if record_id := elm.dosipas_record_id():
                    barcode_data["level2SignedData"]["level1Data"]["dataSequence"].append({
                        "dataFormat": record_id,
                        "data": elm.record_content()
                    })

            priv_key = self._get_priv_key()
            tbs_bytes = BARCODE_HEADER.encode("Level1DataType", barcode_data["level2SignedData"]["level1Data"])

            if isinstance(priv_key, DSAPrivateKey):
                barcode_data["level2SignedData"]["level1Signature"] = priv_key.sign(tbs_bytes, hashes.SHA256())
            elif isinstance(priv_key, EllipticCurvePrivateKey):
                barcode_data["level2SignedData"]["level1Signature"] = priv_key.sign(tbs_bytes, ECDSA(hashes.SHA256()))
            elif isinstance(priv_key, Ed25519PrivateKey):
                barcode_data["level2SignedData"]["level1Signature"] = priv_key.sign(tbs_bytes)

            barcode_bytes = BARCODE_HEADER.encode("UicBarcodeHeader", barcode_data)

        elif self.event.settings.uic_barcode_format == "tlb":
            assert isinstance(priv_key, DSAPrivateKey)

            barcode_contents = bytearray()
            for elm in barcode_elements:
                if record_id := elm.tlb_record_id():
                    assert len(record_id) == 6
                    barcode_contents.extend(record_id.encode("ascii"))
                    version = elm.tlb_record_version()
                    assert 0 < version < 100
                    barcode_contents.extend(f"{version:02d}".encode("ascii"))
                    data = elm.record_content()
                    data_len = len(data) + 12
                    assert data_len < 10000
                    barcode_contents.extend(f"{data_len:04d}".encode("ascii"))
                    barcode_contents.extend(data)

            compressed_contents = zlib.compress(barcode_contents)
            signature = priv_key.sign(compressed_contents, hashes.SHA256())
            signature_tlv = ber_tlv.tlv.Tlv.parse(signature)
            assert len(signature_tlv) == 1
            assert signature_tlv[0][0] == 48
            assert len(signature_tlv[0][1]) == 2
            assert signature_tlv[0][1][0][0] == 2
            assert signature_tlv[0][1][1][0] == 2
            r = signature_tlv[0][1][0][1]
            s = signature_tlv[0][1][1][1]

            barcode_bytes = bytearray(b"#UT02")
            signing_rics = int(self.event.settings.uic_barcode_security_provider_rics, 10)
            assert len(self.event.settings.uic_barcode_key_id) <= 5
            barcode_bytes.extend(f"{signing_rics:04d}".encode("ascii"))
            try:
                key_id = int(self.event.settings.uic_barcode_key_id, 10)
                barcode_bytes.extend(f"{key_id:05d}".encode("ascii"))
            except ValueError:
                barcode_bytes.extend(f"{self.event.settings.uic_barcode_key_id:>5}".encode("ascii"))
            for _ in range(0, 32 - len(r)):
                barcode_bytes.append(0)
            barcode_bytes.extend(r)
            for _ in range(0, 32 - len(s)):
                barcode_bytes.append(0)
            barcode_bytes.extend(s)
            barcode_bytes.extend(f"{len(compressed_contents):04d}".encode("ascii"))
            barcode_bytes.extend(compressed_contents)

        else:
            raise NotImplementedError()

        if self.event.settings.uic_barcode_encoding == "raw":
            return base64.b64encode(barcode_bytes).decode("ascii")
        elif self.event.settings.uic_barcode_encoding == "b45":
            barcode_ascii = base45.b45encode(barcode_bytes).decode("ascii")
            return f"UIC:B45:{barcode_ascii}"
        else:
            raise NotImplementedError()
