import base64

from rest_framework import serializers
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat


class UICBarcodeField(serializers.Field):
    @staticmethod
    def get_attribute(instance):
        return instance.ticket_secret_generator

    @staticmethod
    def to_representation(value):
        return value == "uic-barcodes"


class UICPublicKeyField(serializers.Field):
    @staticmethod
    def get_attribute(instance):
        return load_pem_private_key(instance.uic_barcode_private_key.encode(), None).public_key()

    @staticmethod
    def to_representation(value):
        return base64.b64encode(value.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode()


class UICSecurityProviderField(serializers.Field):
    @staticmethod
    def get_attribute(instance):
        if instance.uic_barcode_security_provider_org_code:
            return {
                "type": "org-code",
                "org_code": instance.uic_barcode_security_provider_org_code,
            }
        elif instance.uic_barcode_security_provider_alt_code_value:
            return {
                "type": "alt-code",
                "table": instance.uic_barcode_security_provider_alt_code_table or "*PRETIX",
                "value": instance.uic_barcode_security_provider_alt_code_value,
            }
        else:
            return None

    @staticmethod
    def to_representation(value):
        return value


class UICKeyIDField(serializers.Field):
    @staticmethod
    def get_attribute(instance):
        try:
            return int(instance.uic_barcode_key_id, 10)
        except ValueError:
            return instance.uic_barcode_key_id

    @staticmethod
    def to_representation(value):
        return value


def event_settings_fields():
    return {
        "scan_uic_barcode": UICBarcodeField(read_only=True),
        "uic_public_key": UICPublicKeyField(read_only=True),
        "uic_security_provider": UICSecurityProviderField(read_only=True),
        "uic_key_id": UICKeyIDField(read_only=True),
    }

def order_position_fields(order_position):
    if hasattr(order_position, "totp"):
        return {
            "uic_totp_key": base64.b16encode(order_position.totp.totp_key).decode("ascii"),
            "uic_totp_period": order_position.event.settings.get("ticketoutput_google-wallet-uic_rotating_barcode_period", as_type=int),
        }
    return {}