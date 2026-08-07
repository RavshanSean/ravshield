import pytest

from ravshield.enums import Severity
from ravshield.intel.email import (
    EmailReputationRecord,
    EmailReputationService,
    EmailReputationStore,
)


def test_store_add_and_get_record():
    store = EmailReputationStore()

    record = EmailReputationRecord(
        email="Scammer@Example.COM",
        malicious=True,
        severity=Severity.HIGH,
        confidence=0.95,
        tags={"phishing"},
        source="unit-test",
    )

    store.add(record)

    stored = store.get("scammer@example.com")

    assert stored is not None
    assert stored.email == "scammer@example.com"
    assert stored.malicious is True
    assert stored.severity == Severity.HIGH
    assert stored.confidence == 0.95
    assert stored.tags == {"phishing"}
    assert stored.source == "unit-test"


def test_store_normalizes_lookup():
    store = EmailReputationStore()

    record = EmailReputationRecord(
        email="user@example.com",
        malicious=False,
        severity=Severity.INFO,
        confidence=0.80,
    )

    store.add(record)

    assert store.exists("USER@EXAMPLE.COM") is True


def test_store_remove_record():
    store = EmailReputationStore()

    record = EmailReputationRecord(
        email="bad@example.com",
        malicious=True,
        severity=Severity.HIGH,
        confidence=0.90,
    )

    store.add(record)

    removed = store.remove("BAD@EXAMPLE.COM")

    assert removed is not None
    assert removed.email == "bad@example.com"
    assert store.exists("bad@example.com") is False


def test_record_rejects_invalid_confidence():
    with pytest.raises(ValueError):
        EmailReputationRecord(
            email="user@example.com",
            malicious=False,
            severity=Severity.INFO,
            confidence=1.5,
        )


def test_service_returns_unknown_result():
    service = EmailReputationService()

    result = service.check("unknown@example.com")

    assert result.email == "unknown@example.com"
    assert result.known is False
    assert result.malicious is False
    assert result.severity == Severity.INFO
    assert result.confidence == 0.0
    assert result.tags == set()
    assert result.source is None


def test_service_returns_known_malicious_result():
    service = EmailReputationService()

    service.add_record(
        EmailReputationRecord(
            email="scammer@example.com",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"phishing", "impersonation"},
            source="unit-test",
        )
    )

    result = service.check("SCAMMER@EXAMPLE.COM")

    assert result.email == "scammer@example.com"
    assert result.known is True
    assert result.malicious is True
    assert result.severity == Severity.CRITICAL
    assert result.confidence == 0.99
    assert result.tags == {"phishing", "impersonation"}
    assert result.source == "unit-test"


def test_service_rejects_invalid_email():
    service = EmailReputationService()

    with pytest.raises(ValueError):
        service.check("not-an-email")