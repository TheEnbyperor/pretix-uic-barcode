import niquests
from pretix.base.models import Order, OrderPosition, Event
from pretix.base.services.tasks import EventTask
from pretix.base.settings import GlobalSettingsObject
from pretix.celery_app import app

from . import ticket_output_google_wallet, ticket_output_apple_wallet, models

SESSION = niquests.Session(happy_eyeballs=True)

def notify_apple_device(device: models.AppleDevice):
    gs = GlobalSettingsObject()
    r = SESSION.post(f"https://api.push.apple.com/3/device/{device.push_token}", headers={
        "apns-push-type": "alert",
        "apns-priority": "10"
    }, json={
        "aps": {
            "content-available": 1
        }
    }, cert=(
        gs.settings.get("uic_barcode_apple_wallet_certificate").read(),
        gs.settings.get("uic_barcode_apple_wallet_private_key")
    ))
    if r.status_code == 410:
        device.delete()
        return
    r.raise_for_status()


@app.task(base=EventTask, acks_late=True)
def notify_apple(event: Event, position_pk):
    position = OrderPosition.objects.get(pk=position_pk)
    for registration in position.apple_registrations.all():
        notify_apple_device(registration.device)


@app.task(base=EventTask, acks_late=True)
def update_ticket_output(event: Event, position_pk):
    position = OrderPosition.objects.get(pk=position_pk)
    google_wallet = ticket_output_google_wallet.GoogleWalletOutput(position.event)
    apple_wallet = ticket_output_apple_wallet.AppleWalletOutput(position.event)

    if google_wallet.client:
        google_wallet.generate_pass(position, force=False)
    if apple_wallet.signer:
        apple_wallet.generate_pass(position)
        notify_apple.apply_async(kwargs={"event": event.pk, "position_pk": position.pk}, countdown=5)


@app.task(base=EventTask, acks_late=True)
def update_ticket_output_all(event: Event, order_pk):
    order = Order.objects.get(pk=order_pk)
    for position in order.positions_with_tickets:
        update_ticket_output.apply_async(kwargs={"event": event.pk, "position_pk": position.pk})