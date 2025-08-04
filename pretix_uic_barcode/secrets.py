import string
from django.utils.crypto import get_random_string
from pretix.base.secrets import BaseTicketSecretGenerator
from pretix.base.models import Item, ItemVariation, SubEvent


class UICSecretGenerator(BaseTicketSecretGenerator):
    verbose_name = "UIC barcode"
    identifier = "uic-barcodes"
    use_revocation_list = True

    @staticmethod
    def generate_secret(item: Item, variation: ItemVariation = None, subevent: SubEvent = None,
                        current_secret: str = None, force_invalidate=False, **kwargs) -> str:
        if current_secret and not force_invalidate:
            return current_secret
        return get_random_string(
            length=6,
            allowed_chars=f"{string.ascii_uppercase}{string.digits}"
        )
