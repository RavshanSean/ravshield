from __future__ import annotations

from dataclasses import dataclass, field


AUTH_FAIL_TOKENS = {
    "fail",
    "softfail",
    "permerror",
    "temperror",
    "neutral",
    "none",
}

AUTH_PASS_TOKENS = {
    "pass",
}


@dataclass(slots=True)
class EmailAuthResult:
    """
    Offline parse of SPF / DKIM / DMARC authentication headers.
    """

    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    signals: set[str] = field(default_factory=set)
    details: dict[str, object] = field(default_factory=dict)

    @property
    def suspicious(self) -> bool:
        return bool(self.signals)


def _normalize_headers(
    headers: dict[str, str],
) -> dict[str, str]:
    return {
        key.lower().strip(): value.strip()
        for key, value in headers.items()
    }


def _extract_result_token(value: str) -> str | None:
    lowered = value.lower()

    for token in (
        "pass",
        "fail",
        "softfail",
        "neutral",
        "none",
        "permerror",
        "temperror",
    ):
        if token in lowered:
            return token

    return None


def _parse_authentication_results(
    value: str,
) -> dict[str, str]:
    """
    Parse a subset of RFC 8601 Authentication-Results methods.
    """

    results: dict[str, str] = {}
    lowered = value.lower()

    for method in ("spf", "dkim", "dmarc"):
        marker = f"{method}="
        index = lowered.find(marker)

        if index < 0:
            continue

        remainder = lowered[index + len(marker) :]
        token = remainder.split()[0].strip(";")
        token = token.split("(")[0].strip()
        results[method] = token

    return results


def analyze_email_auth_headers(
    headers: dict[str, str],
) -> EmailAuthResult:
    """
    Inspect authentication-related email headers without DNS lookups.

    Accepts common header names:
    - Authentication-Results
    - Received-SPF
    - DKIM-Signature (presence only)
    """

    normalized = _normalize_headers(headers)
    signals: set[str] = set()
    details: dict[str, object] = {}

    spf = None
    dkim = None
    dmarc = None

    auth_results = normalized.get("authentication-results")

    if auth_results:
        parsed = _parse_authentication_results(auth_results)
        spf = parsed.get("spf")
        dkim = parsed.get("dkim")
        dmarc = parsed.get("dmarc")
        details["authentication_results"] = auth_results

    received_spf = normalized.get("received-spf")

    if received_spf and spf is None:
        spf = _extract_result_token(received_spf)
        details["received_spf"] = received_spf

    if "dkim-signature" in normalized and dkim is None:
        dkim = "present"
        details["dkim_signature_present"] = True

    if spf in AUTH_FAIL_TOKENS:
        signals.add("spf_fail")

    if dkim in AUTH_FAIL_TOKENS:
        signals.add("dkim_fail")

    if dmarc in AUTH_FAIL_TOKENS:
        signals.add("dmarc_fail")

    if spf is None and dkim is None and dmarc is None:
        signals.add("auth_headers_missing")

    if spf in AUTH_PASS_TOKENS:
        details["spf_pass"] = True

    if dkim in AUTH_PASS_TOKENS:
        details["dkim_pass"] = True

    if dmarc in AUTH_PASS_TOKENS:
        details["dmarc_pass"] = True

    return EmailAuthResult(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        signals=signals,
        details=details,
    )
