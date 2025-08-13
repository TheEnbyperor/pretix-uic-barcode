import tempfile
import typing
import cryptography.x509
import cryptography.hazmat.primitives.serialization
from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile, UploadedFile
from django.utils.translation import gettext_lazy as _
from pretix.control.forms import ClearableBasenameFileInput
from . import pkpass


class AppleWalletCertificateFileField(forms.FileField):
    widget = ClearableBasenameFileInput

    def clean(self, value, *args, **kwargs):
        value = super().clean(value, *args, **kwargs)
        if isinstance(value, UploadedFile):
            value.open("rb")
            value.seek(0)
            content = value.read()

            try:
                cert = cryptography.x509.load_der_x509_certificate(content)
            except ValueError:
                raise forms.ValidationError("Invalid certificate")

            private_key = pkpass.get_private_key()

            try:
                signer = pkpass.PKPassSigner(private_key, cert)
            except ValueError as e:
                raise forms.ValidationError(f"Invalid certificate: {e}")

            pass_type_id = signer.pass_type_id.replace(".", "_")
            return SimpleUploadedFile(f"apple_wallet_{pass_type_id}.crt", cert.public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.PEM
            ), "application/pkix-cert")
        return value


class PNGImageField(forms.FileField):
    widget = ClearableBasenameFileInput

    def __init__(self, *args, image_name: typing.Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.image_name = image_name

    def clean(self, value, *args, **kwargs):
        value = super().clean(value, *args, **kwargs)
        if isinstance(value, UploadedFile):
            try:
                from PIL import Image
            except ImportError:
                return value

            value.open("rb")
            value.seek(0)
            try:
                with (
                    Image.open(value, formats=settings.PILLOW_FORMATS_IMAGE) as im,
                    tempfile.NamedTemporaryFile("rb", suffix=".png") as tmpfile,
                ):
                    im.save(tmpfile.name)
                    tmpfile.seek(0)
                    return SimpleUploadedFile(
                        self.image_name or "picture", tmpfile.read(), "image/png"
                    )
            except IOError:
                raise ValidationError(
                    _("The file you uploaded could not be converted to PNG format.")
                )

        return value