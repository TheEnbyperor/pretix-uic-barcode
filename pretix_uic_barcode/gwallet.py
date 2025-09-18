import json
import google.auth.crypt
import google.oauth2.service_account
import googleapiclient.discovery
from pretix.base.settings import GlobalSettingsObject


def get_client():
    gs = GlobalSettingsObject()
    if creds_json := gs.settings.get("uic_barcode_google_wallet_credentials", None):
        creds = google.oauth2.service_account.Credentials.from_service_account_info(
            json.loads(creds_json),
            scopes=['https://www.googleapis.com/auth/wallet_object.issuer']
        )
        return googleapiclient.discovery.build("walletobjects", "v1", credentials=creds)

    return None

def get_signer():
    gs = GlobalSettingsObject()
    if creds_json := gs.settings.get("uic_barcode_google_wallet_credentials", None):
        return google.auth.crypt.RSASigner.from_service_account_info(
            json.loads(creds_json),
        )

    return None