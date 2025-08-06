import pretix.base.models
import logging
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
from rest_framework import viewsets, serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView


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