from collections.abc import Iterator

from ravshield.enums import Verdict
from ravshield.intel.ioc import (
    normalize_indicator_type,
    normalize_indicator_value,
)
from ravshield.intel.threat_record import ThreatRecord
from ravshield.models import DetectionFinding


class ThreatIntelligenceStore:
    """
    In-memory store for contextual threat-intelligence records.

    A database or external-feed adapter can replace this store later
    without changing the public lookup interface.
    """

    def __init__(self) -> None:
        self._records: dict[
            tuple[str, str],
            ThreatRecord,
        ] = {}

    @staticmethod
    def _build_key(
        indicator_type: str,
        value: str,
    ) -> tuple[str, str]:
        normalized_type = normalize_indicator_type(
            indicator_type
        )
        normalized_value = normalize_indicator_value(
            normalized_type,
            value,
        )

        return normalized_type, normalized_value

    def add(self, record: ThreatRecord) -> None:
        key = self._build_key(
            record.indicator_type,
            record.value,
        )

        self._records[key] = record

    def get(
        self,
        indicator_type: str,
        value: str,
    ) -> ThreatRecord | None:
        try:
            key = self._build_key(
                indicator_type,
                value,
            )
        except ValueError:
            return None

        return self._records.get(key)

    def contains(
        self,
        indicator_type: str,
        value: str,
    ) -> bool:
        return self.get(
            indicator_type,
            value,
        ) is not None

    def remove(
        self,
        indicator_type: str,
        value: str,
    ) -> bool:
        try:
            key = self._build_key(
                indicator_type,
                value,
            )
        except ValueError:
            return False

        return self._records.pop(key, None) is not None

    def all(self) -> list[ThreatRecord]:
        return list(self._records.values())

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[ThreatRecord]:
        return iter(self._records.values())


def build_reputation_finding(
    record: ThreatRecord,
) -> DetectionFinding:
    titles = {
        Verdict.MALICIOUS: "Known malicious indicator",
        Verdict.SUSPICIOUS: "Known suspicious indicator",
        Verdict.SAFE: "Known trusted indicator",
        Verdict.UNKNOWN: "Known indicator with unknown verdict",
    }

    family_text = (
        f" Malware family: {record.malware_family}."
        if record.malware_family
        else ""
    )

    description = (
        record.description
        or (
            f"Threat intelligence from {record.source} "
            f"classified this {record.indicator_type} "
            f"as {record.verdict.value}.{family_text}"
        )
    )

    return DetectionFinding(
        code=f"reputation_{record.verdict.value}",
        title=titles[record.verdict],
        description=description,
        severity=record.severity,
        confidence=record.confidence,
        evidence={
            "indicator_type": record.indicator_type,
            "value": record.value,
            "verdict": record.verdict.value,
            "source": record.source,
            "malware_family": record.malware_family,
            "first_seen": record.first_seen.isoformat(),
            "last_seen": record.last_seen.isoformat(),
            "tags": list(record.tags),
        },
    )


def lookup_reputation(
    store: ThreatIntelligenceStore,
    indicator_type: str,
    value: str,
) -> DetectionFinding | None:
    record = store.get(
        indicator_type,
        value,
    )

    if record is None:
        return None

    return build_reputation_finding(record)