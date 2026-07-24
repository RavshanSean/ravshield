import pytest

from ravshield.models import Severity

from ravshield.intel.url import (
    URLReputationRecord,
    URLReputationService,
    URLReputationStore,
    normalize_url,
    validate_url,
)


def test_normalize_lowercase():
    url = "HTTPS://Example.COM"

    assert normalize_url(url) == "https://example.com/"


def test_remove_default_https_port():
    url = "https://example.com:443/login"

    assert normalize_url(url) == "https://example.com/login"


def test_remove_fragment():
    url = "https://example.com/page#section"

    assert normalize_url(url) == "https://example.com/page"


def test_sort_query_parameters():
    url = "https://example.com/search?b=2&a=1"

    assert normalize_url(url) == "https://example.com/search?a=1&b=2"


def test_validate_good_url():
    assert validate_url("https://example.com") is True


def test_reject_private_ip():
    with pytest.raises(ValueError):
        validate_url("http://192.168.1.5")


def test_reject_loopback():
    with pytest.raises(ValueError):
        validate_url("http://127.0.0.1")


def test_reject_ftp():
    with pytest.raises(ValueError):
        validate_url("ftp://example.com")


def test_empty_url():
    with pytest.raises(ValueError):
        validate_url("")
        
def test_url_reputation_store_add_and_get():
    store = URLReputationStore()

    record = URLReputationRecord(
        url="https://evil.example/",
        malicious=True,
        severity=Severity.HIGH,
        confidence=0.95,
        tags={"phishing"},
    )

    store.add(record)

    stored_record = store.get("https://evil.example/")

    assert stored_record is not None
    assert stored_record.malicious is True
    assert stored_record.severity == Severity.HIGH
    assert stored_record.confidence == 0.95
    assert "phishing" in stored_record.tags


def test_url_reputation_store_exists():
    store = URLReputationStore()

    record = URLReputationRecord(
        url="https://evil.example/",
        malicious=True,
        severity=Severity.HIGH,
        confidence=0.95,
    )

    store.add(record)

    assert store.exists("https://evil.example/") is True
    assert store.exists("https://unknown.example/") is False


def test_url_reputation_store_remove():
    store = URLReputationStore()

    record = URLReputationRecord(
        url="https://evil.example/",
        malicious=True,
        severity=Severity.HIGH,
        confidence=0.95,
    )

    store.add(record)
    store.remove("https://evil.example/")

    assert store.exists("https://evil.example/") is False


def test_reputation_service_unknown_url():
    service = URLReputationService()

    result = service.check("https://unknown.example")

    assert result.url == "https://unknown.example/"
    assert result.known is False
    assert result.malicious is False
    assert result.severity == Severity.INFO
    assert result.confidence == 0.0
    assert result.tags == set()
    assert result.source is None


def test_reputation_service_known_malicious_url():
    service = URLReputationService()

    record = URLReputationRecord(
        url="HTTPS://Evil.Example:443/login#top",
        malicious=True,
        severity=Severity.CRITICAL,
        confidence=0.99,
        tags={"phishing", "credential-theft"},
        source="test-feed",
    )

    service.add_record(record)

    result = service.check("https://evil.example/login")

    assert result.url == "https://evil.example/login"
    assert result.known is True
    assert result.malicious is True
    assert result.severity == Severity.CRITICAL
    assert result.confidence == 0.99
    assert result.tags == {"phishing", "credential-theft"}
    assert result.source == "test-feed"


def test_reputation_service_normalizes_before_lookup():
    service = URLReputationService()

    record = URLReputationRecord(
        url="https://example.com/search?b=2&a=1",
        malicious=False,
        severity=Severity.INFO,
        confidence=0.80,
    )

    service.add_record(record)

    result = service.check(
        "HTTPS://EXAMPLE.COM:443/search?a=1&b=2#section"
    )

    assert result.known is True
    assert result.url == "https://example.com/search?a=1&b=2"


def test_reputation_service_rejects_private_ip():
    service = URLReputationService()

    with pytest.raises(ValueError):
        service.check("http://192.168.1.10")