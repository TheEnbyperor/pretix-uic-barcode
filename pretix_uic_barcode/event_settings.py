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
        return value.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


class UICSecurityProviderField(serializers.Field):
    @staticmethod
    def get_attribute(instance):
        if instance.uic_barcode_security_provider_rics:
            return int(instance.uic_barcode_security_provider_rics, 10)
        else:
            return instance.uic_barcode_security_provider_ia5

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
