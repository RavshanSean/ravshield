from __future__ import annotations

import ipaddress


def validate_ip(value: str) -> bool:
    """
    Return True when the value is a valid IPv4 or IPv6 address.
    """

    if not isinstance(value, str):
        return False

    candidate = value.strip()

    if not candidate:
        return False

    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False

    return True