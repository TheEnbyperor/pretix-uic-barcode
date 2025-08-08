import secrets
from django.db import models
from pretix.base.models import OrderPosition

def generate_totp_secret():
    return secrets.token_bytes(20)

class AppleWalletPass(models.Model):
    order_position = models.OneToOneField(OrderPosition, on_delete=models.CASCADE, related_name="apple_wallet_pass", db_index=True)
    pass_type_id = models.CharField(max_length=255)
    pass_serial = models.CharField(max_length=255)
    contents_hash = models.BinaryField()
    last_modified = models.DateTimeField()

    class Meta:
        unique_together = (('pass_type_id', 'pass_serial'),)
        index_together = (('pass_type_id', 'pass_serial'),)


class AppleDevice(models.Model):
    device_id = models.CharField(max_length=255, primary_key=True, verbose_name="Device ID")
    push_token = models.CharField(max_length=255)

    def __str__(self):
        return self.device_id


class ApplePassRegistration(models.Model):
    order_position = models.ForeignKey(OrderPosition, on_delete=models.CASCADE, related_name="apple_registrations", db_index=True)
    device = models.ForeignKey(AppleDevice, on_delete=models.CASCADE, related_name="registrations", db_index=True)

    class Meta:
        unique_together = (("order_position", "device"),)


class OrderPositionTotp(models.Model):
    order_position = models.OneToOneField(OrderPosition, on_delete=models.CASCADE, related_name="totp", db_index=True)
    totp_key = models.BinaryField(default=generate_totp_secret)