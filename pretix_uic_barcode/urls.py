from django.urls import path
from pretix.api import urls
from . import api, views

urlpatterns = [
    path(
        "control/event/<str:organizer>/<str:event>/settings/uic_barcode/",
        views.SettingsView.as_view(),
        name="settings",
    ),
    path(
        "control/grobal/settings/apple_wallet.csr",
        views.apple_wallet_csr,
        name="apple_wallet_csr"
    )
]

urls.orga_router.register('uic_keys', api.UICKeyViewSet, basename='uic_keys')