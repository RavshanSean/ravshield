from __future__ import annotations

import ipaddress


def normalize_ip(value: str) -> str:
    """
    Normalize an IPv4 or IPv6 address into canonical form.
    """

    if not isinstance(value, str):
        raise TypeError("IP address must be a string.")

    candidate = value.strip()

    if not candidate:
        raise ValueError("IP address cannot be empty.")

    return str(ipaddress.ip_address(candidate))