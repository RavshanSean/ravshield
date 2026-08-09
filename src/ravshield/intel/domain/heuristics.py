from __future__ import annotations

import math
from dataclasses import dataclass

from ravshield.intel.domain.normalize import normalize_domain
from ravshield.intel.text_match import (
    brand_impersonation_matches,
    keyword_matches,
)

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "country",
    "click",
    "work",
    "gq",
    "tk",
    "cf",
    "ml",
    "ga",
    "top",
    "xyz",
    "buzz",
    "rest",
    "support",
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

WATCHED_BRANDS = {
    "paypal",
    "apple",
    "google",
    "microsoft",
    "amazon",
    "facebook",
    "netflix",
    "instagram",
    "whatsapp",
    "blockchain",
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

    # suspicious keywords on token boundaries
    matches = keyword_matches(domain, SUSPICIOUS_KEYWORDS)

    if matches:
        signals.append("suspicious_keywords")
        details["keywords"] = matches

    brand_parts: list[str] = []

    for label in labels[:-1]:
        brand_parts.extend(
            part
            for part in label.replace("_", "-").split("-")
            if part
        )

    brand_hits = brand_impersonation_matches(
        brand_parts,
        WATCHED_BRANDS,
    )

    if brand_hits:
        signals.append("brand_impersonation")
        details["brand_impersonation"] = brand_hits

    # suspicious tld
    tld = labels[-1]

    if tld in SUSPICIOUS_TLDS:
        signals.append("suspicious_tld")
        details["tld"] = tld

    # entropy — only on the registrable-ish left-most labels,
    # and only when long enough to avoid short-label FP.
    hostname = "".join(labels[:-1])

    ent = _entropy(hostname)

    details["entropy"] = round(ent, 2)

    if len(hostname) >= 8 and ent > 3.8:
        signals.append("high_entropy")

    return DomainHeuristicResult(
        domain=domain,
        signals=signals,
        details=details,
    )
