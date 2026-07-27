from __future__ import annotations

import math
from dataclasses import dataclass

from ravshield.intel.domain.normalize import normalize_domain

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "country",
    "click",
    "work",
    "gq",
    "tk",
    "cf",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "secure",
    "verify",
    "update",
    "password",
    "account",
    "paypal",
    "bank",
    "wallet",
    "signin",
}


@dataclass(slots=True)
class DomainHeuristicResult:
    domain: str
    signals: list[str]
    details: dict[str, object]

    @property
    def suspicious(self) -> bool:
        return bool(self.signals)


def _entropy(text: str) -> float:
    if not text:
        return 0.0

    counts = {}

    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1

    length = len(text)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def analyze_domain_heuristics(domain: str) -> DomainHeuristicResult:
    domain = normalize_domain(domain)

    signals = []
    details = {}

    labels = domain.split(".")

    # excessive subdomains
    if len(labels) > 4:
        signals.append("excessive_subdomains")

    # punycode
    if any(label.startswith("xn--") for label in labels):
        signals.append("punycode")

    # suspicious keywords
    lowered = domain.lower()

    matches = [
        word
        for word in SUSPICIOUS_KEYWORDS
        if word in lowered
    ]

    if matches:
        signals.append("suspicious_keywords")
        details["keywords"] = matches

    # suspicious tld
    tld = labels[-1]

    if tld in SUSPICIOUS_TLDS:
        signals.append("suspicious_tld")
        details["tld"] = tld

    # entropy
    hostname = "".join(labels[:-1])

    ent = _entropy(hostname)

    details["entropy"] = round(ent, 2)

    if ent > 3.8:
        signals.append("high_entropy")

    return DomainHeuristicResult(
        domain=domain,
        signals=signals,
        details=details,
    )