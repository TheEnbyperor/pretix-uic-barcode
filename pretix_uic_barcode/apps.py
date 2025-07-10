from django.utils.translation import gettext_lazy
from . import __version__

try:
    from pretix.base.plugins import PluginConfig
except ImportError:
    raise RuntimeError("Please use pretix 2.7 or above to run this plugin!")


class PluginApp(PluginConfig):
    default = True
    name = "pretix_uic_barcode"
    verbose_name = "UIC Barcodes"

    class PretixPluginMeta:
        name = gettext_lazy("UIC Barcodes")
        author = "Q Misell"
        description = gettext_lazy("Generate ticket barcodes as UIC barcodes")
        visible = True
        experimental = True
        version = __version__
        category = "FEATURE"
        compatibility = "pretix>=2.7.0"
        settings_links = []
        navigation_links = []

    def ready(self):
        from . import signals  # NOQA
