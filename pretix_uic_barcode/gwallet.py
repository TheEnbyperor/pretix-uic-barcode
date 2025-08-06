import json
import google.auth.crypt
import google.oauth2.service_account
import googleapiclient.discovery
from pretix.base.settings import GlobalSettingsObject

GOOGLE_WALLET_CLIENT = None
GOOGLE_WALLET_SIGNER = None

def get_client():
    global GOOGLE_WALLET_CLIENT

    if GOOGLE_WALLET_CLIENT is not None:
        return GOOGLE_WALLET_CLIENT

    gs = GlobalSettingsObject()
    if creds_json := gs.settings.get("uic_barcode_google_wallet_credentials", None):
        creds = google.oauth2.service_account.Credentials.from_service_account_info(
            json.loads(creds_json),
            scopes=['https://www.googleapis.com/auth/wallet_object.issuer']
        )
        GOOGLE_WALLET_CLIENT = googleapiclient.discovery.build("walletobjects", "v1", credentials=creds)
        return GOOGLE_WALLET_CLIENT

    return None

def get_signer():
    global GOOGLE_WALLET_SIGNER

    if GOOGLE_WALLET_SIGNER is not None:
        return GOOGLE_WALLET_SIGNER

    gs = GlobalSettingsObject()
    if creds_json := gs.settings.get("uic_barcode_google_wallet_credentials", None):
        GOOGLE_WALLET_SIGNER = google.auth.crypt.RSASigner.from_service_account_info(
            json.loads(creds_json),
        )
        return GOOGLE_WALLET_SIGNER

    return None