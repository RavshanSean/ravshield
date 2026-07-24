from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


ALLOWED_SCHEMES = {
    "http",
    "https",
}


def validate_url(url: str) -> bool:
    """
    Validate whether a URL is safe and structurally acceptable
    for RavShield URL intelligence processing.

    This function validates format only.
    It does not visit or scan the website.
    """

    if not isinstance(url, str):
        raise TypeError("URL must be a string.")

    candidate = url.strip()

    if not candidate:
        raise ValueError("URL cannot be empty.")

    parsed = urlsplit(candidate)

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("Only HTTP and HTTPS URLs are allowed.")

    if not parsed.hostname:
        raise ValueError("URL must include a hostname.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port.") from exc

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("URL port must be between 1 and 65535.")

    hostname = parsed.hostname

    if hostname is None:
        raise ValueError("URL must include a hostname.")

    try:
        ip_address = ipaddress.ip_address(hostname)
    except ValueError:
        ip_address = None

    if ip_address is not None:
        if ip_address.is_loopback:
            raise ValueError("Loopback IP addresses are not allowed.")

        if ip_address.is_private:
            raise ValueError("Private IP addresses are not allowed.")

        if ip_address.is_link_local:
            raise ValueError("Link-local IP addresses are not allowed.")

        if ip_address.is_reserved:
            raise ValueError("Reserved IP addresses are not allowed.")

        if ip_address.is_multicast:
            raise ValueError("Multicast IP addresses are not allowed.")

        if ip_address.is_unspecified:
            raise ValueError("Unspecified IP addresses are not allowed.")

    return True