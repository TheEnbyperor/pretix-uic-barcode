import abc
import base64
import json
import niquests
import logging
import datetime
import dataclasses
import pytz
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key, load_der_public_key
from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponse
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.http import http_date, parse_http_date_safe
from django_scopes import scope
from pretix.base.models import Organizer, Order, OrderPosition, Event
from rest_framework import viewsets, serializers, status
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.generics import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_base64_binaryfield.fields import Base64BinaryField
from . import pkpass, ticket_output_apple_wallet, models


class KeySerializer(serializers.Serializer):
    security_provider = serializers.CharField()
    key_id = serializers.CharField()
    public_key = serializers.CharField()


class KeysSerializer(serializers.Serializer):
    keys = KeySerializer(many=True)


class UICKeyViewSet(viewsets.ViewSet):
    @staticmethod
    def list(request, organizer):
        organizer = Organizer.objects.get(slug=organizer)

        seen_keys = set()
        keys = []
        for event in organizer.events.all():
            if not event.settings.uic_barcode_key_id:
                continue
            else:
                key_id = (event.settings.uic_barcode_security_provider_rics or event.settings.uic_barcode_security_provider_ia5, event.settings.uic_barcode_key_id)
                if key_id in seen_keys:
                    continue
                seen_keys.add(key_id)

                keys.append({
                    "security_provider": key_id[0],
                    "key_id": key_id[1],
                    "public_key": load_pem_private_key(event.settings.uic_barcode_private_key.encode(), None).public_key()
                        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
                })

        s = KeysSerializer(instance={
            "keys": keys,
        }, context={
            'request': request
        })
        return Response(s.data)


class LogSerializer(serializers.Serializer):
    logs = serializers.ListField(child=serializers.CharField())


class ApplePassAuthentication(TokenAuthentication):
    model = OrderPosition
    keyword = "ApplePass"

    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            order_position = model.objects.get(web_secret=key)
        except model.DoesNotExist:
            raise AuthenticationFailed('Invalid token.')

        return AnonymousUser(), order_position


class AppleLog(APIView):
    authentication_classes = ()
    permission_classes = ()

    @staticmethod
    def post(request):
        logs = LogSerializer(data=request.data)
        if logs.is_valid():
            for log in logs.validated_data["logs"]:
                logging.warning(log)

            return Response(status=status.HTTP_200_OK)
        else:
            return Response(logs.errors, status=status.HTTP_400_BAD_REQUEST)

class AuthenticatedAppleView(APIView):
    authentication_classes = (ApplePassAuthentication,)
    permission_classes = ()

    def __init__(self):
        super().__init__()
        self.signer = pkpass.get_signer()

    def check_authentication(self, request, pass_type, pass_serial):
        if not isinstance(request.auth, OrderPosition):
            return Response(status=status.HTTP_403_FORBIDDEN)

        if pass_type != self.signer.pass_type_id:
            return Response(status=status.HTTP_404_NOT_FOUND)

        serial_parts = pass_serial.split("-", 1)
        if len(serial_parts) != 2:
            return Response(status=status.HTTP_404_NOT_FOUND)

        organiser_slug, order_code = serial_parts
        try:
            organizer = Organizer.objects.get(slug=organiser_slug)
        except Organizer.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        if request.auth.code != order_code or request.auth.organizer != organizer:
            return Response(status=status.HTTP_403_FORBIDDEN)

        return None

class AppleFetchPass(AuthenticatedAppleView):
    def get(self, request, pass_type, pass_serial):
        if resp := self.check_authentication(request, pass_type, pass_serial):
            return resp

        last_modified_obj, _ = models.AppleWalletPass.objects.get_or_create(
            pass_type_id=self.signer.pass_type_id,
            pass_serial=pass_serial,
            defaults={
                "last_modified": timezone.now()
            }
        )

        if if_modified_since := request.META.get("HTTP_IF_MODIFIED_SINCE"):
            if_modified_since = parse_http_date_safe(if_modified_since)
            if if_modified_since >= int(last_modified_obj.last_modified.timestamp()):
                return Response(status=status.HTTP_304_NOT_MODIFIED)

        output_generator = ticket_output_apple_wallet.AppleWalletOutput(request.auth.event)
        pk_pass = output_generator.generate_pass(request.auth)
        last_modified_obj.refresh_from_db()

        resp = HttpResponse(
            pk_pass.get_buffer(),
            content_type="application/vnd.apple.pkpass"
        )
        resp["last-modified"] = http_date(int(last_modified_obj.last_modified.timestamp()))
        return resp


class ApplePassListSerializer(serializers.Serializer):
    lastUpdated = serializers.CharField()
    serialNumbers = serializers.ListField(child=serializers.CharField())


class ApplePassList(APIView):
    authentication_classes = ()
    permission_classes = ()

    def __init__(self):
        super().__init__()
        self.signer = pkpass.get_signer()

    def get(self, request, device_id, pass_type):
        device, _ = models.AppleDevice.objects.get_or_create(device_id=device_id)

        if pass_type != self.signer.pass_type_id:
            return Response(status=status.HTTP_404_NOT_FOUND)

        last_updated = request.GET.get("passesUpdatedSince")
        if last_updated:
            try:
                last_updated = datetime.datetime.fromtimestamp(int(last_updated), pytz.utc)
            except ValueError:
                return Response(status=status.HTTP_400_BAD_REQUEST)

        regs = device.registrations.all()
        if last_updated:
            regs = regs.filter(order_position__apple_wallet_pass__last_modified__gt=last_updated)

        passes = [reg.order_position.apple_wallet_pass for reg in regs]
        new_last_updated = max(
            (p.last_modified for p in passes),
            default=datetime.datetime.now(pytz.utc)
        )

        return Response(ApplePassListSerializer(instance={
            "lastUpdated": str(int(new_last_updated.astimezone(pytz.utc).timestamp()) + 1),
            "serialNumbers": [str(p.pass_serial) for p in passes],
        }).data)


class AppleRegisterSerializer(serializers.Serializer):
    pushToken = serializers.CharField()


class AppleRegisterPass(AuthenticatedAppleView):
    def post(self, request, device_id, pass_type, pass_serial):
        if resp := self.check_authentication(request, pass_type, pass_serial):
            return resp

        registration = AppleRegisterSerializer(data=request.data)
        if not registration.is_valid():
            return Response(registration.errors, status=status.HTTP_400_BAD_REQUEST)

        device, _ = models.AppleDevice.objects.update_or_create(
            device_id=device_id,
            defaults={
                "push_token": registration.validated_data["pushToken"],
            }
        )
        device.registrations.get_or_create(order_position=request.auth)
        return Response(status=status.HTTP_200_OK)

    def delete(self, request, device_id, pass_type, pass_serial):
        if resp := self.check_authentication(request, pass_type, pass_serial):
            return resp

        device, _ = models.AppleDevice.objects.get_or_create(device_id=device_id)
        device.registrations.filter(order_position=request.auth).delete()
        return Response(status=status.HTTP_200_OK)


class GooglePaySigningKey(serializers.Serializer):
    signedKey = serializers.CharField()
    signatures = serializers.ListField(child=Base64BinaryField())

class GooglePayTokenSerializer(serializers.Serializer):
    protocolVersion = serializers.CharField()
    signature = Base64BinaryField()
    intermediateSigningKey = GooglePaySigningKey()
    signedMessage = serializers.CharField()

@dataclasses.dataclass
class GooglePayRootKey:
    public_key: PublicKeyTypes
    protocol_version: str
    expiration: datetime.datetime

class GooglePayRootStore:
    ROOT_KEYS_URL = "https://pay.google.com/gp/m/issuer/keys"

    @cached_property
    def root_keys(self):
        r = niquests.get(self.ROOT_KEYS_URL)
        r.raise_for_status()
        keys = r.json()["keys"]
        return [GooglePayRootKey(
            public_key=load_der_public_key(base64.b64decode(key["keyValue"])),
            protocol_version=key["protocolVersion"],
            expiration=datetime.datetime.fromtimestamp(int(key["keyExpiration"]) / 1000, pytz.utc),
        ) for key in keys]


class GooglePayCallback(abc.ABC):
    SENDER_ID = "GooglePayPasses"
    SIGNING_PROTOCOL = "ECv2SigningOnly"
    ROOT_STORE = GooglePayRootStore()

    @abc.abstractmethod
    def process_callback(self, message):
        raise NotImplementedError()

    def post(self, request, organizer, event):
        organizer = get_object_or_404(Organizer, slug=organizer)
        with scope(organizer=organizer):
            event = get_object_or_404(Event, slug=event)
        issuer_id = event.settings.get("ticketoutput_google-wallet-uic_issuer_id")

        token = GooglePayTokenSerializer(data=request.data)
        if not token.is_valid():
            return Response(token.errors, status=status.HTTP_400_BAD_REQUEST)
        token = token.validated_data

        if token["protocolVersion"] != self.SIGNING_PROTOCOL:
            return Response({
                "protocolVersion": "Invalid protocol version",
            }, status=status.HTTP_400_BAD_REQUEST)

        now = datetime.datetime.now(pytz.utc)
        root_keys = list(filter(lambda k: k.protocol_version == token["protocolVersion"] and k.expiration >= now,
                                self.ROOT_STORE.root_keys))

        sender_id = self.SENDER_ID.encode("utf-8")
        protocol_version = token["protocolVersion"].encode("utf-8")
        signed_key = token["intermediateSigningKey"]["signedKey"].encode("utf-8")
        intermediate_signing_key_tbs = bytes([
            *len(sender_id).to_bytes(4, byteorder="little"),
            *sender_id,
            *len(protocol_version).to_bytes(4, byteorder="little"),
            *protocol_version,
            *len(signed_key).to_bytes(4, byteorder="little"),
            *signed_key,
        ])

        key_verified = False
        for signature in token["intermediateSigningKey"]["signatures"]:
            for root_key in root_keys:
                try:
                    root_key.public_key.verify(signature, intermediate_signing_key_tbs, ec.ECDSA(hashes.SHA256()))
                    key_verified = True
                except InvalidSignature:
                    pass

        if not key_verified:
            return Response({
                "intermediateSigningKey": "Invalid signature",
            }, status=status.HTTP_400_BAD_REQUEST)

        intermediate_signing_key_data = json.loads(token["intermediateSigningKey"]["signedKey"])
        intermediate_signing_key_expiration = datetime.datetime.fromtimestamp(
            int(intermediate_signing_key_data["keyExpiration"]) / 1000, pytz.utc)
        if intermediate_signing_key_expiration < now:
            return Response({
                "intermediateSigningKey": "Expired key",
            }, status=status.HTTP_400_BAD_REQUEST)
        intermediate_signing_key = load_der_public_key(base64.b64decode(intermediate_signing_key_data["keyValue"]))

        signed_message = token["signedMessage"].encode("utf-8")
        recipient_id = issuer_id.encode("utf-8")
        signed_message_tbs = bytes([
            *len(sender_id).to_bytes(4, byteorder="little"),
            *sender_id,
            *len(recipient_id).to_bytes(4, byteorder="little"),
            *recipient_id,
            *len(protocol_version).to_bytes(4, byteorder="little"),
            *protocol_version,
            *len(signed_message).to_bytes(4, byteorder="little"),
            *signed_message,
        ])

        try:
            intermediate_signing_key.verify(token["signature"], signed_message_tbs, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return Response({
                "signature": "Invalid signature",
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            message = json.loads(token["signedMessage"])
        except ValueError:
            return Response({
                "signedMessage": "Invalid JSON",
            }, status=status.HTTP_400_BAD_REQUEST)

        return self.process_callback(message)

class GoogleCallbackSerializer(serializers.Serializer):
    classId = serializers.CharField()
    objectId = serializers.CharField()
    expTimeMillis = serializers.IntegerField()
    eventType = serializers.CharField()
    nonce = serializers.CharField()

class GoogleCallback(GooglePayCallback, APIView):
    authentication_classes = ()
    permission_classes = ()

    def process_callback(self, data):
        data = GoogleCallbackSerializer(data=data)
        if not data.is_valid():
            return Response(data.errors, status=status.HTTP_400_BAD_REQUEST)
        data = data.validated_data

        expiration = datetime.datetime.fromtimestamp(int(data["expTimeMillis"]) / 1000, pytz.utc)
        if expiration < datetime.datetime.now(pytz.utc):
            return Response({
                "expiration": "Expired message",
            }, status=status.HTTP_400_BAD_REQUEST)

        models.GoogleEventLog.objects.get_or_create(
            class_id=data["classId"],
            object_id=data["objectId"],
            nonce=data["nonce"],
            defaults={
                "event_type": data["eventType"],
            }
        )

        return Response(status=status.HTTP_202_ACCEPTED)
