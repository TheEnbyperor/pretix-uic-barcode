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
    ),

    path("api/apple_wallet/v1/log", api.AppleLog.as_view(), name="apple_wallet_log"),
    path("api/apple_wallet/v1/passes/<str:pass_type>/<str:pass_serial>", api.AppleFetchPass.as_view(), name="apple_wallet_fetch_pass"),
    path("api/apple_wallet/v1/devices/<str:device_id>/registrations/<str:pass_type>", api.ApplePassList.as_view(), name="apple_wallet_pass_list"),
    path("api/apple_wallet/v1/devices/<str:device_id>/registrations/<str:pass_type>/<str:pass_serial>", api.AppleRegisterPass.as_view(), name="apple_wallet_register_pass"),

    path("api_google_wallet/v1/event/<str:organizer>/<str:event>/callback", api.GoogleCallback.as_view(), name="google_wallet_callback"),
]

urls.orga_router.register('uic_keys', api.UICKeyViewSet, basename='uic_keys')