import hashlib
import json
import typing
import zipfile
import io
import datetime
import secrets
import asn1crypto.core
import asn1crypto.algos
import asn1crypto.cms
import asn1crypto.tsp
import asn1crypto.x509
import cryptography.x509
import cryptography.x509.extensions
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.asymmetric.dsa
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.serialization.pkcs7
import cryptography.x509.oid
import niquests
from django.contrib.staticfiles import finders
from django.core.files import File
from pretix.base.settings import GlobalSettingsObject

from . import __version__

TSP_URL = "http://timestamp.apple.com/ts01"
PRIV_KEY_TYPE = typing.Union[
    cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey,
    cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey,
    cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
]

WWDR_G4_NAME = cryptography.x509.Name.from_rfc4514_string(
    "C=US,O=Apple Inc.,OU=G4,CN=Apple Worldwide Developer Relations Certification Authority")


SESSION = niquests.Session(happy_eyeballs=True, timeout=5)

class PKPassSigner:
    team_id: str
    pass_type_id: str
    pass_signer_name: str
    private_key: PRIV_KEY_TYPE
    certificate: cryptography.x509.Certificate
    wwdr_certificate: cryptography.x509.Certificate

    def __init__(self, private_key: PRIV_KEY_TYPE, certificate: cryptography.x509.Certificate):
        if isinstance(private_key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
            pass
        elif isinstance(private_key, cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey):
            pass
        elif isinstance(private_key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey):
            pass
        else:
            raise ValueError("unsupported private key type")

        if certificate.public_key() != private_key.public_key():
            raise ValueError("certificate does not match private key")

        self.private_key = private_key
        self.certificate = certificate

        org = certificate.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.ORGANIZATION_NAME)
        if not org:
            raise ValueError("certificate missing organization name")
        self.pass_signer_name = org[0].value

        team_id = certificate.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)
        if not team_id:
            raise ValueError("certificate missing Team ID")
        self.team_id = team_id[0].value

        pass_type_id = certificate.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.USER_ID)
        if not pass_type_id:
            raise ValueError("certificate missing Pass Type ID")
        self.pass_type_id = pass_type_id[0].value

        if certificate.issuer == WWDR_G4_NAME:
            self.wwdr_certificate = cryptography.x509.load_pem_x509_certificate(
                open(finders.find("pretix_uic_barcode/wwdrg4.pem"), "rb").read()
            )
        else:
            raise ValueError(f"unknown WWDR CA: {certificate.issuer.rfc4514_string()}")


def get_private_key():
    gs = GlobalSettingsObject()
    if pk := gs.settings.get("uic_barcode_apple_wallet_private_key", None):
        return cryptography.hazmat.primitives.serialization.load_pem_private_key(pk.encode(), None)

    pk = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    gs.settings.set("uic_barcode_apple_wallet_private_key", pk.private_bytes(
        cryptography.hazmat.primitives.serialization.Encoding.PEM,
        cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
        cryptography.hazmat.primitives.serialization.NoEncryption(),
    ).decode())
    return pk


def get_signer():
    gs = GlobalSettingsObject()
    if not gs.settings.get("uic_barcode_apple_wallet_certificate", None):
        return None
    private_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(
        gs.settings.get("uic_barcode_apple_wallet_private_key").encode(), None
    )
    cert = cryptography.x509.load_pem_x509_certificate(gs.settings.get(
        "uic_barcode_apple_wallet_certificate", as_type=File, binary_file=True
    ).read())
    return PKPassSigner(private_key, cert)


class PKPass:
    def __init__(self):
        self.data = {}
        self.manifest = {}
        self.signature = None

    def add_file(self, filename: str, data: bytes):
        file_hash = hashlib.sha1(data).hexdigest()
        self.data[filename] = data
        self.manifest[filename] = file_hash

    def contents_hash(self):
        contents = ":".join([v for _, v in sorted(self.manifest.items(), key=lambda x: x[0])])
        return hashlib.sha256(contents.encode()).digest()

    def sign(self, signer: PKPassSigner):
        manifest = json.dumps(self.manifest).encode("utf-8")
        self.data["manifest.json"] = manifest
        manifest_digest = cryptography.hazmat.primitives.hashes.Hash(
            cryptography.hazmat.primitives.hashes.SHA512()
        )
        manifest_digest.update(manifest)
        manifest_digest = manifest_digest.finalize()
        if isinstance(signer.private_key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
            signature_alg = asn1crypto.algos.SignedDigestAlgorithmId("rsassa_pkcs1v15")
        elif isinstance(signer.private_key, cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey):
            signature_alg = asn1crypto.algos.SignedDigestAlgorithmId("dsa")
        elif isinstance(signer.private_key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey):
            signature_alg = asn1crypto.algos.SignedDigestAlgorithmId("ecdsa")

        signed_attrs = asn1crypto.cms.CMSAttributes([
            asn1crypto.cms.CMSAttribute({
                "type": asn1crypto.cms.CMSAttributeType("content_type"),
                "values": [asn1crypto.cms.ContentType("data")]
            }),
            asn1crypto.cms.CMSAttribute({
                "type": asn1crypto.cms.CMSAttributeType("signing_time"),
                "values": [asn1crypto.core.UTCTime(datetime.datetime.now(datetime.UTC))]
            }),
            asn1crypto.cms.CMSAttribute({
                "type": asn1crypto.cms.CMSAttributeType("message_digest"),
                "values": [asn1crypto.core.OctetString(manifest_digest)]
            })
        ])
        if isinstance(signer.private_key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
            signature = signer.private_key.sign(
                signed_attrs.dump(),
                cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
                cryptography.hazmat.primitives.hashes.SHA512()
            )
        elif isinstance(signer.private_key, cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey):
            signature = signer.private_key.sign(
                signed_attrs.dump(),
                cryptography.hazmat.primitives.hashes.SHA512()
            )
        elif isinstance(signer.private_key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey):
            signature = signer.private_key.sign(
                signed_attrs.dump(),
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                    cryptography.hazmat.primitives.hashes.SHA512()
                )
            )

        timestamp_nonce = int.from_bytes(secrets.token_bytes(8), "big")
        timestamp_digest = cryptography.hazmat.primitives.hashes.Hash(
            cryptography.hazmat.primitives.hashes.SHA512()
        )
        timestamp_digest.update(signature)
        timestamp_digest = timestamp_digest.finalize()
        timestamp_req = asn1crypto.tsp.TimeStampReq({
            "version": asn1crypto.tsp.Version("v1"),
            "message_imprint": asn1crypto.tsp.MessageImprint({
                "hash_algorithm": asn1crypto.algos.DigestAlgorithm({"algorithm": "sha512"}),
                "hashed_message": timestamp_digest,
            }),
            "cert_req": True,
            "nonce": timestamp_nonce,
        })
        r = SESSION.post(TSP_URL, headers={
            "Content-Type": "application/timestamp-query",
            "User-Agent": f"Pretix-UIC-Barcode/{__version__}",
        }, data=timestamp_req.dump())
        r.raise_for_status()
        if r.headers["Content-Type"] != "application/timestamp-reply":
            raise ValueError("Unexpected content type reply from timestamping server")
        timestamp_resp = asn1crypto.tsp.TimeStampResp.load(r.content)
        if timestamp_resp["status"]["status"].native not in ("granted", "granted_with_mods"):
            raise ValueError(f"Error response from timestamping server: {timestamp_resp['status']['status_string']}")
        tst = timestamp_resp["time_stamp_token"]
        if tst["content_type"].native != "signed_data":
            raise ValueError(f"Unexpected content type from timestamping server: {tst['content_type']}")
        tst_signed_data = tst["content"]
        if tst_signed_data["encap_content_info"]["content_type"].native != "tst_info":
            raise ValueError(
                f"Unexpected content type from timestamping server: {tst_signed_data['encap_content_info']['content_type']}")
        tst_info = asn1crypto.tsp.TSTInfo.load(bytes(tst_signed_data["encap_content_info"]["content"]))
        if "nonce" not in tst_info or tst_info["nonce"].native != timestamp_nonce:
            raise ValueError("Mismatched nonce from timestamping server")

        cms_signature = asn1crypto.cms.ContentInfo({
            "content_type": asn1crypto.cms.ContentType("signed_data"),
            "content": asn1crypto.cms.SignedData({
                "version": asn1crypto.cms.CMSVersion("v1"),
                "digest_algorithms": asn1crypto.cms.DigestAlgorithms([
                    asn1crypto.algos.DigestAlgorithm({"algorithm": "sha512"})
                ]),
                "encap_content_info": asn1crypto.cms.ContentInfo({
                    "content_type": asn1crypto.cms.ContentType("data")
                }),
                "certificates": asn1crypto.cms.CertificateSet([
                    asn1crypto.cms.CertificateChoices({
                        "certificate": asn1crypto.x509.Certificate.load(signer.wwdr_certificate.public_bytes(
                            encoding=cryptography.hazmat.primitives.serialization.Encoding.DER))
                    }),
                    asn1crypto.cms.CertificateChoices({
                        "certificate": asn1crypto.x509.Certificate.load(signer.certificate.public_bytes(
                            encoding=cryptography.hazmat.primitives.serialization.Encoding.DER))
                    })
                ]),
                "signer_infos": asn1crypto.cms.SignerInfos([asn1crypto.cms.SignerInfo({
                    "version": asn1crypto.cms.CMSVersion("v3"),
                    "sid": asn1crypto.cms.SignerIdentifier({
                        "subject_key_identifier": signer.certificate.extensions.get_extension_for_class(
                            cryptography.x509.extensions.SubjectKeyIdentifier).value.key_identifier,
                    }),
                    "digest_algorithm": asn1crypto.algos.DigestAlgorithm({"algorithm": "sha512"}),
                    "signed_attrs": signed_attrs,
                    "signature_algorithm": asn1crypto.algos.SignedDigestAlgorithm({
                        "algorithm": signature_alg
                    }),
                    "signature": signature,
                    "unsigned_attrs": asn1crypto.cms.CMSAttributes([
                        asn1crypto.cms.CMSAttribute({
                            "type": asn1crypto.cms.CMSAttributeType("signature_time_stamp_token"),
                            "values": [tst]
                        }),
                    ])
                })])
            })
        })
        self.data["signature"] = cms_signature.dump()

    def get_buffer(self) -> bytes:
        zip_buffer = io.BytesIO()
        zip_file = zipfile.ZipFile(zip_buffer, "w")
        for filename, data in self.data.items():
            zip_file.writestr(filename, data)
        zip_file.close()
        return zip_buffer.getvalue()


class MultiPKPass:
    def __init__(self):
        self.counter = 1
        self.zip_buffer = io.BytesIO()
        self.zip = zipfile.ZipFile(self.zip_buffer, "w")

    def add_pkpass(self, pkpass: typing.Union[PKPass, bytes]):
        if isinstance(pkpass, PKPass):
            self.zip.writestr(f"pass-{self.counter}.pkpass", pkpass.get_buffer())
        else:
            self.zip.writestr(f"pass-{self.counter}.pkpass", pkpass)
        self.counter += 1

    def get_buffer(self) -> bytes:
        self.zip.close()
        return self.zip_buffer.getvalue()
