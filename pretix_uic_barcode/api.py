import pretix.base.models
import logging
import datetime

import pytz
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponse
from django.utils import timezone
from django.utils.http import http_date, parse_http_date_safe
from pretix.base.models import Organizer, Order, OrderPosition
from rest_framework import viewsets, serializers, status
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.views import APIView
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
        organizer = pretix.base.models.Organizer.objects.get(slug=organizer)

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
