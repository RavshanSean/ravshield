import pytest

from ravshield.enums import Severity
from ravshield.intel import (
    IOC,
    IOCStore,
    is_valid_indicator,
    match_indicators,
    match_ioc,
)


VALID_SHA256 = "a" * 64


def create_test_ioc() -> IOC:
    return IOC(
        value=VALID_SHA256.upper(),
        indicator_type="SHA256",
        severity=Severity.HIGH,
        source="RavShield Test Intelligence",
        confidence=95,
    )


def test_ioc_normalizes_type_and_value():
    ioc = create_test_ioc()

    assert ioc.indicator_type == "sha256"
    assert ioc.value == VALID_SHA256
    assert ioc.confidence == 95


def test_ioc_rejects_unsupported_type():
    with pytest.raises(ValueError):
        IOC(
            value="example",
            indicator_type="unsupported",
            severity=Severity.LOW,
            source="test",
            confidence=50,
        )


def test_ioc_rejects_invalid_hash():
    with pytest.raises(ValueError):
        IOC(
            value="not-a-valid-hash",
            indicator_type="sha256",
            severity=Severity.HIGH,
            source="test",
            confidence=90,
        )


def test_ioc_rejects_invalid_confidence():
    with pytest.raises(ValueError):
        IOC(
            value=VALID_SHA256,
            indicator_type="sha256",
            severity=Severity.HIGH,
            source="test",
            confidence=150,
        )


def test_indicator_validation():
    assert is_valid_indicator(
        "sha256",
        VALID_SHA256,
    ) is True

    assert is_valid_indicator(
        "ip",
        "8.8.8.8",
    ) is True

    assert is_valid_indicator(
        "domain",
        "example.com",
    ) is True

    assert is_valid_indicator(
        "url",
        "https://example.com/login",
    ) is True

    assert is_valid_indicator(
        "email",
        "analyst@example.com",
    ) is True

    assert is_valid_indicator(
        "cve",
        "CVE-2025-12345",
    ) is True

    assert is_valid_indicator(
        "ip",
        "999.999.999.999",
    ) is False


def test_ioc_store_add_and_lookup():
    store = IOCStore()
    ioc = create_test_ioc()

    store.add(ioc)

    assert len(store) == 1
    assert store.contains(
        "SHA256",
        VALID_SHA256.upper(),
    )
    assert store.get(
        "sha256",
        VALID_SHA256,
    ) == ioc


def test_ioc_store_remove():
    store = IOCStore()
    ioc = create_test_ioc()

    store.add(ioc)

    assert store.remove(
        "sha256",
        VALID_SHA256,
    ) is True

    assert len(store) == 0
    assert store.remove(
        "sha256",
        VALID_SHA256,
    ) is False


def test_match_ioc_returns_detection_finding():
    store = IOCStore()
    store.add(create_test_ioc())

    finding = match_ioc(
        store,
        "sha256",
        VALID_SHA256,
    )

    assert finding is not None
    assert finding.code == "ioc_match"
    assert finding.severity is Severity.HIGH
    assert finding.confidence == 95
    assert finding.evidence["value"] == VALID_SHA256


def test_match_ioc_returns_none_for_unknown_indicator():
    store = IOCStore()

    finding = match_ioc(
        store,
        "sha256",
        "b" * 64,
    )

    assert finding is None


def test_match_multiple_indicators():
    store = IOCStore()

    store.add(
        IOC(
            value="malicious-example.com",
            indicator_type="domain",
            severity=Severity.HIGH,
            source="RavShield Test Intelligence",
            confidence=90,
        )
    )

    store.add(
        IOC(
            value="8.8.8.8",
            indicator_type="ip",
            severity=Severity.LOW,
            source="RavShield Test Intelligence",
            confidence=50,
        )
    )

    findings = match_indicators(
        store,
        [
            ("domain", "MALICIOUS-EXAMPLE.COM"),
            ("ip", "8.8.8.8"),
            ("domain", "unknown-example.com"),
        ],
    )

    assert len(findings) == 2
    assert findings[0].code == "ioc_match"
    assert findings[1].code == "ioc_match"