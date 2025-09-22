from pretix.base.services.placeholders import BaseTextPlaceholder
from . import ticket_output_google_wallet

class GoogleWalletOrderPlaceholder(BaseTextPlaceholder):
    identifier = "google_wallet_link_order"
    required_context = [
        "event",
        "order"
    ]

    def render(self, context):
        output = ticket_output_google_wallet.GoogleWalletOutput(context["event"])
        _, _, url = output.generate_order(context["order"])
        return url

    def render_sample(self, event):
        return "GOOGLE WALLET LINK"


class GoogleWalletOrderPositionPlaceholder(BaseTextPlaceholder):
    identifier = "google_wallet_link_order_position"
    required_context = [
        "event",
        "position"
    ]

    def render(self, context):
        output = ticket_output_google_wallet.GoogleWalletOutput(context["event"])
        _, _, url = output.generate(context["position"])
        return url

    def render_sample(self, event):
        return "GOOGLE WALLET LINK"
