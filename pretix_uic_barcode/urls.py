from django.urls import path
from pretix.api import urls
from .views import SettingsView
from . import api

urlpatterns = [
    path(
        "control/event/<str:organizer>/<str:event>/settings/uic_barcode/",
        SettingsView.as_view(),
        name="settings",
    ),
]

urls.orga_router.register('uic_keys', api.UICKeyViewSet, basename='uic_keys')