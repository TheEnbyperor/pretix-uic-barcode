import typing
import base45
import zlib
import ber_tlv.tlv
import pathlib
import asn1tools
import inspect
import datetime
from django.utils.functional import cached_property
from pretix.base.models import OrderPosition
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from . import elements

ROOT = pathlib.Path(__file__).parent
BARCODE_HEADER = asn1tools.compile_files([ROOT / "asn1" / "uicBarcodeHeader_v2.0.1.asn"], codec="uper")
BARCODE_MMTD_HEADER = asn1tools.compile_files([ROOT / "asn1" / "uicBarcodeHeader_v3.0.0.asn", ROOT / "asn1" / "uicGeneralData_v1.0.0.asn"], codec="uper")
BARCODE_TOTP = asn1tools.compile_files([ROOT / "asn1" / "uicTotp.asn"], codec="uper")

BASE41_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*-.:"

def base41_encode(data: bytes) -> str:
    output = ""

    for i in range(0, len(data), 2):
        x = data[i] + (256 * data[i + 1]) if i < len(data) - 1 else 0
        output += BASE41_ALPHABET[x % 41]
        x //= 41
        output += BASE41_ALPHABET[x % 41]
        output += BASE41_ALPHABET[x // 41]
    return output

def base41_decode(data: str) -> bytes:
    output = bytearray()
    if len(data) % 3 != 0:
        return b""
    for i in range(0, len(data), 3):
        x = BASE41_ALPHABET.index(data[i]) + (41 * BASE41_ALPHABET.index(data[i + 1])) + (41 * 41 * BASE41_ALPHABET.index(data[i + 2]))
        output.append(x % 256)
        output.append(x // 256)
    return bytes(output)


class UICBarcodeGenerator:
    def __init__(self, event):
        self.event = event

    def _get_priv_key(self):
        return load_pem_private_key(self.event.settings.uic_barcode_private_key.encode(), None)

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

    def sign(self, barcode_elements: typing.List[elements.UICBarcodeElement], totp: bool = False):
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

            if self.event.settings.uic_barcode_security_provider_org_code:
                try:
                    rics = int(self.event.settings.uic_barcode_security_provider_org_code, 10)
                    barcode_data["level2SignedData"]["level1Data"]["securityProviderNum"] = rics
                except ValueError:
                    barcode_data["level2SignedData"]["level1Data"]["securityProviderIA5"] = \
                        self.event.settings.uic_barcode_security_provider_org_code
            elif self.event.settings.uic_barcode_security_provider_alt_code_value:
                barcode_data["level2SignedData"]["level1Data"]["securityProviderIA5"] = \
                    self.event.settings.uic_barcode_security_provider_alt_code_value

            for elm in barcode_elements:
                if record_id := elm.dosipas_record_id():
                    barcode_data["level2SignedData"]["level1Data"]["dataSequence"].append({
                        "dataFormat": record_id,
                        "data": elm.record_content()
                    })

            tbs_bytes = BARCODE_HEADER.encode("Level1DataType", barcode_data["level2SignedData"]["level1Data"])

            if isinstance(priv_key, DSAPrivateKey):
                barcode_data["level2SignedData"]["level1Signature"] = priv_key.sign(tbs_bytes, hashes.SHA256())
            elif isinstance(priv_key, EllipticCurvePrivateKey):
                barcode_data["level2SignedData"]["level1Signature"] = priv_key.sign(tbs_bytes, ECDSA(hashes.SHA256()))
            elif isinstance(priv_key, Ed25519PrivateKey):
                barcode_data["level2SignedData"]["level1Signature"] = priv_key.sign(tbs_bytes)

            if totp:
                totp_offset = 0
                while True:
                    totp_data = {
                        "padding": (b"\x00", totp_offset),
                        "totp": b"XXXXXXXX",
                    }
                    barcode_data["level2SignedData"]["level2Data"] = {
                        "dataFormat": "_5101TOTP",
                        "data": BARCODE_TOTP.encode("PretixTotp", totp_data),
                    }
                    barcode_bytes = BARCODE_HEADER.encode("UicBarcodeHeader", barcode_data)
                    if barcode_bytes.endswith(b"XXXXXXXX"):
                        barcode_bytes = barcode_bytes[:-8] + b"{totp_value_0}"
                        break
                    else:
                        totp_offset += 1
            else:
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

        elif self.event.settings.uic_barcode_format == "mmtd":
            if self.event.settings.uic_barcode_security_provider_org_code:
                company_code = ("orgCode", self.event.settings.uic_barcode_security_provider_org_code)
            elif self.event.settings.uic_barcode_security_provider_alt_code_value:
                company_code = ("otherCode", {
                    "codeTable": self.event.settings.uic_barcode_security_provider_alt_code_table or "*PRETIX",
                    "code": self.event.settings.uic_barcode_security_provider_alt_code_value,
                })
            else:
                raise NotImplementedError()

            inner_data = {
                "data": []
            }

            for elm in barcode_elements:
                if record_id := elm.dosipas_record_id():
                    inner_data["data"].append({
                        "dataFormat": record_id,
                        "data": elm.record_content()
                    })

            tbs_inner_data = BARCODE_MMTD_HEADER.encode("BarcodeData", inner_data)

            if isinstance(priv_key, DSAPrivateKey):
                if priv_key.key_size == 1024:
                    r, s = decode_dss_signature(priv_key.sign(tbs_inner_data, hashes.SHA1()))
                    signature = ("dsa1", {
                        "r": r.to_bytes(20, "big"),
                        "s": s.to_bytes(20, "big"),
                    })
                elif priv_key.key_size == 2048:
                    r, s = decode_dss_signature(priv_key.sign(tbs_inner_data, hashes.SHA256()))
                    signature = ("dsa256", {
                        "r": r.to_bytes(32, "big"),
                        "s": s.to_bytes(32, "big"),
                    })
                else:
                    raise NotImplementedError(f"Unsupported DSA key size: {priv_key.key_size}")
            elif isinstance(priv_key, EllipticCurvePrivateKey):
                if priv_key.curve.name == "secp256r1":
                    r, s = decode_dss_signature(priv_key.sign(tbs_inner_data, ECDSA(hashes.SHA256())))
                    signature = ("es256", {
                        "r": r.to_bytes(32, "big"),
                        "s": s.to_bytes(32, "big"),
                    })
                elif priv_key.curve.name == "secp256k1":
                    r, s = decode_dss_signature(priv_key.sign(tbs_inner_data, ECDSA(hashes.SHA256())))
                    signature = ("es256k", {
                        "r": r.to_bytes(32, "big"),
                        "s": s.to_bytes(32, "big"),
                    })
                elif priv_key.curve.name == "secp384":
                    r, s = decode_dss_signature(priv_key.sign(tbs_inner_data, ECDSA(hashes.SHA384())))
                    signature = ("es384", {
                        "r": r.to_bytes(48, "big"),
                        "s": s.to_bytes(48, "big"),
                    })
                elif priv_key.curve.name == "secp521":
                    r, s = decode_dss_signature(priv_key.sign(tbs_inner_data, ECDSA(hashes.SHA512())))
                    signature = ("es384", {
                        "r": r.to_bytes(66, "big"),
                        "s": s.to_bytes(66, "big"),
                    })
                else:
                    raise NotImplementedError(f"Unsupported EC curve: {priv_key.curve.name}")
            elif isinstance(priv_key, Ed25519PrivateKey):
                signature = ("ed25519", priv_key.sign(tbs_inner_data))
            else:
                signature = ("none", None)

            barcode_data = {
                "format": b"U3",
                "contents": {
                    "level2Data": {
                        "level1Data": {
                            "key": {
                                "securityProvider": company_code,
                                "keyId": int(self.event.settings.uic_barcode_key_id, 10)
                            },
                            "barcodeData": ("standard", {
                                "data": inner_data,
                                "signature": signature,
                            })
                        },
                        "level2Data": []
                    }
                }
            }

            if totp:
                totp_offset = 0
                while True:
                    totp_data = {
                        "padding": (b"\x00", totp_offset),
                        "totp": b"XXXXXXXX",
                    }
                    barcode_data["contents"]["level2Data"]["level2Data"] = [{
                        "dataFormat": "_5101TOTP",
                        "data": BARCODE_TOTP.encode("PretixTotp", totp_data),
                    }]
                    barcode_bytes = BARCODE_MMTD_HEADER.encode("UICBarcodeHeader", barcode_data)
                    if barcode_bytes.endswith(b"XXXXXXXX"):
                        barcode_bytes = barcode_bytes[:-8] + b"{totp_value_0}"
                        break
                    else:
                        totp_offset += 1
            else:
                barcode_bytes = BARCODE_MMTD_HEADER.encode("UICBarcodeHeader", barcode_data)

        else:
            raise NotImplementedError()

        if self.event.settings.uic_barcode_encoding == "raw":
            return barcode_bytes
        elif self.event.settings.uic_barcode_encoding == "b41":
            barcode_ascii = base41_encode(barcode_bytes)
            return f"{self.event.settings.uic_barcode_qr_url_prefix}$UIC:{barcode_ascii}".encode("ascii")
        elif self.event.settings.uic_barcode_encoding == "b45":
            barcode_ascii = base45.b45encode(barcode_bytes).decode("ascii")
            return f"UIC:B45:{barcode_ascii}".encode("ascii")
        else:
            raise NotImplementedError()

    def generate_barcode(
            self, order_position: OrderPosition = None, totp: bool = False
    ) -> bytes:
        barcode_elements = []
        for generator in self.barcode_element_generators:
            kwargs = {}
            params = inspect.signature(generator.generate_element).parameters
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
            if "has_totp" in params:
                kwargs["has_totp"] = totp
            if elm := generator.generate_element(**kwargs):
                barcode_elements.append(elm)

        return self.sign(barcode_elements, totp)