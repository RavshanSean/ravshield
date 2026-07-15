from datetime import datetime, timedelta, timezone

import pytest

from ravshield.enums import Severity, Verdict
from ravshield.intel import (
    ThreatIntelligenceStore,
    ThreatRecord,
    build_reputation_finding,
    lookup_reputation,
)


VALID_SHA256 = "d" * 64
NOW = datetime.now(timezone.utc)


def create_threat_record() -> ThreatRecord:
    return ThreatRecord(
        indicator_type="SHA256",
        value=VALID_SHA256.upper(),
        verdict=Verdict.MALICIOUS,
        severity=Severity.CRITICAL,
        confidence=98,
        source="RavShield Community Intelligence",
        first_seen=NOW - timedelta(days=10),
        last_seen=NOW,
        malware_family="ExampleRansom",
        description=(
            "Known ransomware sample observed in test intelligence."
        ),
        tags=(
            "Ransomware",
            "Encrypted Payload",
            "ransomware",
        ),
    )


def test_threat_record_normalization():
    record = create_threat_record()

    assert record.indicator_type == "sha256"
    assert record.value == VALID_SHA256
    assert record.tags == (
        "ransomware",
        "encrypted payload",
    )


def test_threat_record_rejects_invalid_confidence():
    with pytest.raises(ValueError):
        ThreatRecord(
            indicator_type="sha256",
            value=VALID_SHA256,
            verdict=Verdict.MALICIOUS,
            severity=Severity.HIGH,
            confidence=150,
            source="test",
            first_seen=NOW,
            last_seen=NOW,
        )


def test_threat_record_rejects_invalid_timeline():
    with pytest.raises(ValueError):
        ThreatRecord(
            indicator_type="sha256",
            value=VALID_SHA256,
            verdict=Verdict.MALICIOUS,
            severity=Severity.HIGH,
            confidence=90,
            source="test",
            first_seen=NOW,
            last_seen=NOW - timedelta(days=1),
        )


def test_threat_intelligence_store_lookup():
    store = ThreatIntelligenceStore()
    record = create_threat_record()

    store.add(record)

    result = store.get(
        "SHA256",
        VALID_SHA256.upper(),
    )

    assert result == record
    assert len(store) == 1


def test_build_reputation_finding():
    record = create_threat_record()

    finding = build_reputation_finding(record)

    assert finding.code == "reputation_malicious"
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence == 98
    assert finding.evidence["malware_family"] == (
        "ExampleRansom"
    )
    assert finding.evidence["source"] == (
        "RavShield Community Intelligence"
    )


def test_lookup_reputation_returns_finding():
    store = ThreatIntelligenceStore()
    store.add(create_threat_record())

    finding = lookup_reputation(
        store,
        "sha256",
        VALID_SHA256,
    )

    assert finding is not None
    assert finding.code == "reputation_malicious"
    assert finding.evidence["value"] == VALID_SHA256


def test_lookup_reputation_returns_none_for_unknown():
    store = ThreatIntelligenceStore()

    finding = lookup_reputation(
        store,
        "sha256",
        "e" * 64,
    )

    assert finding is None