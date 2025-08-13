import urllib3
import idna


def idna_encode_url(url: str):
    parts = urllib3.util.parse_url(url)
    host = idna.encode(parts.host).decode()
    new_url = urllib3.util.Url(parts.scheme, parts.auth, host, parts.port, parts.path, parts.query, parts.fragment)
    return new_url.url