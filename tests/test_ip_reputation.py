import pytest

from ravshield.enums import Severity
from ravshield.intel.ip import (
    IPReputationRecord,
    IPReputationService,
    IPReputationStore,
)


def test_store_add_and_get_record():
    store = IPReputationStore()

    record = IPReputationRecord(
        ip="8.8.8.8",
        malicious=True,
        severity=Severity.HIGH,
        confidence=0.95,
        tags={"abuse"},
        source="unit-test",
    )

    store.add(record)

    stored = store.get("8.8.8.8")

    assert stored is not None
    assert stored.ip == "8.8.8.8"
    assert stored.malicious is True
    assert stored.severity == Severity.HIGH
    assert stored.confidence == 0.95
    assert stored.tags == {"abuse"}
    assert stored.source == "unit-test"


def test_store_normalizes_ipv6_lookup():
    store = IPReputationStore()

    record = IPReputationRecord(
        ip="2001:db8::1",
        malicious=False,
        severity=Severity.INFO,
        confidence=0.80,
    )

    store.add(record)

    assert store.exists(
        "2001:0db8:0000:0000:0000:0000:0000:0001"
    ) is True


def test_store_remove_record():
    store = IPReputationStore()

    record = IPReputationRecord(
        ip="1.2.3.4",
        malicious=True,
        severity=Severity.HIGH,
        confidence=0.90,
    )

    store.add(record)

    removed = store.remove("1.2.3.4")

    assert removed is not None
    assert removed.ip == "1.2.3.4"
    assert store.exists("1.2.3.4") is False


def test_record_rejects_invalid_confidence():
    with pytest.raises(ValueError):
        IPReputationRecord(
            ip="8.8.8.8",
            malicious=False,
            severity=Severity.INFO,
            confidence=1.5,
        )


def test_service_returns_unknown_result():
    service = IPReputationService()

    result = service.check("1.1.1.1")

    assert result.ip == "1.1.1.1"
    assert result.known is False
    assert result.malicious is False
    assert result.severity == Severity.INFO
    assert result.confidence == 0.0
    assert result.tags == set()
    assert result.source is None


def test_service_returns_known_malicious_result():
    service = IPReputationService()

    service.add_record(
        IPReputationRecord(
            ip="8.8.8.8",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"botnet", "abuse"},
            source="unit-test",
        )
    )

    result = service.check("8.8.8.8")

    assert result.ip == "8.8.8.8"
    assert result.known is True
    assert result.malicious is True
    assert result.severity == Severity.CRITICAL
    assert result.confidence == 0.99
    assert result.tags == {"botnet", "abuse"}
    assert result.source == "unit-test"


def test_service_rejects_invalid_ip():
    service = IPReputationService()

    with pytest.raises(ValueError):
        service.check("999.999.999.999")