from __future__ import annotations

from dataclasses import dataclass

import ipaddress

from ravshield.intel.ip.normalize import normalize_ip


@dataclass(slots=True)
class IPClassificationResult:
    ip: str
    version: int
    is_private: bool
    is_loopback: bool
    is_link_local: bool
    is_multicast: bool
    is_reserved: bool
    is_global: bool


def classify_ip(value: str) -> IPClassificationResult:
    """
    Classify an IPv4 or IPv6 address.
    """

    normalized = normalize_ip(value)
    address = ipaddress.ip_address(normalized)

    return IPClassificationResult(
        ip=normalized,
        version=address.version,
        is_private=address.is_private,
        is_loopback=address.is_loopback,
        is_link_local=address.is_link_local,
        is_multicast=address.is_multicast,
        is_reserved=address.is_reserved,
        is_global=address.is_global,
    )