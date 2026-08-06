import pytest

from ravshield.enums import Severity
from ravshield.intel.domain import (
    DomainReputationRecord,
    DomainReputationService,
    DomainReputationStore,
)


def test_store_add_and_get_record():
    store = DomainReputationStore()

    record = DomainReputationRecord(
        domain="Evil.COM.",
        malicious=True,
        severity=Severity.HIGH,
        confidence=0.95,
        tags={"phishing"},
        source="unit-test",
    )

    store.add(record)

    stored = store.get("evil.com")

    assert stored is not None
    assert stored.domain == "evil.com"
    assert stored.malicious is True
    assert stored.severity == Severity.HIGH
    assert stored.confidence == 0.95
    assert stored.tags == {"phishing"}
    assert stored.source == "unit-test"


def test_store_normalizes_lookup():
    store = DomainReputationStore()

    record = DomainReputationRecord(
        domain="example.com",
        malicious=False,
        severity=Severity.INFO,
        confidence=0.80,
    )

    store.add(record)

    assert store.exists("EXAMPLE.COM.") is True


def test_store_remove_record():
    store = DomainReputationStore()

    record = DomainReputationRecord(
        domain="evil.com",
        malicious=True,
        severity=Severity.HIGH,
        confidence=0.90,
    )

    store.add(record)

    removed = store.remove("EVIL.COM.")

    assert removed is not None
    assert removed.domain == "evil.com"
    assert store.exists("evil.com") is False


def test_record_rejects_invalid_confidence():
    with pytest.raises(ValueError):
        DomainReputationRecord(
            domain="example.com",
            malicious=False,
            severity=Severity.INFO,
            confidence=1.5,
        )


def test_service_returns_unknown_result():
    service = DomainReputationService()

    result = service.check("unknown.example")

    assert result.domain == "unknown.example"
    assert result.known is False
    assert result.malicious is False
    assert result.severity == Severity.INFO
    assert result.confidence == 0.0
    assert result.tags == set()
    assert result.source is None


def test_service_returns_known_malicious_result():
    service = DomainReputationService()

    service.add_record(
        DomainReputationRecord(
            domain="evil.example",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"malware", "phishing"},
            source="unit-test",
        )
    )

    result = service.check("EVIL.EXAMPLE.")

    assert result.domain == "evil.example"
    assert result.known is True
    assert result.malicious is True
    assert result.severity == Severity.CRITICAL
    assert result.confidence == 0.99
    assert result.tags == {"malware", "phishing"}
    assert result.source == "unit-test"


def test_service_rejects_invalid_domain():
    service = DomainReputationService()

    with pytest.raises(ValueError):
        service.check("not-a-valid-domain")