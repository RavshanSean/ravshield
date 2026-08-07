from __future__ import annotations

from dataclasses import dataclass, field

from ravshield.intel.ip.classify import classify_ip


@dataclass(slots=True)
class IPHeuristicResult:
    ip: str
    signals: set[str] = field(default_factory=set)
    details: dict[str, object] = field(default_factory=dict)

    @property
    def suspicious(self) -> bool:
        return bool(self.signals)


def analyze_ip_heuristics(
    value: str,
) -> IPHeuristicResult:
    """
    Inspect an IP address for security-relevant network characteristics.

    These signals do not prove maliciousness.
    They describe special or potentially unsafe network scopes.
    """

    classification = classify_ip(value)

    signals: set[str] = set()
    details: dict[str, object] = {
        "version": classification.version,
        "is_global": classification.is_global,
    }

    if classification.is_loopback:
        signals.add("loopback")

    if classification.is_private:
        signals.add("private_address")

    if classification.is_link_local:
        signals.add("link_local")

    if classification.is_multicast:
        signals.add("multicast")

    if classification.is_reserved:
        signals.add("reserved")

    return IPHeuristicResult(
        ip=classification.ip,
        signals=signals,
        details=details,
    )