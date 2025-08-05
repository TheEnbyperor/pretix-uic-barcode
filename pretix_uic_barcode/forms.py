import cryptography.x509
import cryptography.hazmat.primitives.serialization
from django import forms
from django.core.files.uploadedfile import SimpleUploadedFile, UploadedFile
from pretix.control.forms import ClearableBasenameFileInput
from . import pkpass


class CertificateFileField(forms.FileField):
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