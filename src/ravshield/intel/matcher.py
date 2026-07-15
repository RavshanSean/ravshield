from ravshield.intel.store import IOCStore
from ravshield.models import DetectionFinding


def match_ioc(
    store: IOCStore,
    indicator_type: str,
    value: str,
) -> DetectionFinding | None:
    """
    Match one observed indicator against the IOC store.
    """

    matched_ioc = store.get(
        indicator_type,
        value,
    )

    if matched_ioc is None:
        return None

    return DetectionFinding(
        code="ioc_match",
        title="Indicator of Compromise matched",
        description=(
            f"A known malicious {matched_ioc.indicator_type} "
            f"indicator matched intelligence from "
            f"{matched_ioc.source}."
        ),
        severity=matched_ioc.severity,
        confidence=matched_ioc.confidence,
        evidence={
            "indicator_type": matched_ioc.indicator_type,
            "value": matched_ioc.value,
            "source": matched_ioc.source,
        },
    )


def match_indicators(
    store: IOCStore,
    indicators: list[tuple[str, str]],
) -> list[DetectionFinding]:
    """
    Match multiple observed indicators against the IOC store.
    """

    findings: list[DetectionFinding] = []

    for indicator_type, value in indicators:
        finding = match_ioc(
            store,
            indicator_type,
            value,
        )

        if finding is not None:
            findings.append(finding)

    return findings