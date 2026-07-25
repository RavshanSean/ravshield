from ravshield.analyzers import create_url_pipeline
from ravshield.enums import Severity, Verdict
from ravshield.intel.url import (
    URLReputationRecord,
    URLReputationService,
)


def test_factory_registers_url_analyzers():
    pipeline = create_url_pipeline()

    result = pipeline.scan(
        "https://example.com/products"
    )

    assert result.analysis_modules == [
        "url_reputation",
        "url_heuristics",
    ]


def test_factory_detects_suspicious_unknown_url():
    pipeline = create_url_pipeline()

    result = pipeline.scan(
        "https://user:pass@"
        "login.verify.account.example.com/%76erify"
    )

    codes = {
        finding.code
        for finding in result.findings
    }

    assert "URL_EMBEDDED_CREDENTIALS" in codes
    assert "URL_SUSPICIOUS_KEYWORDS" in codes
    assert "URL_EXCESSIVE_SUBDOMAINS" in codes
    assert "URL_ENCODED_CHARACTERS" in codes


def test_factory_accepts_custom_reputation_service():
    service = URLReputationService()

    service.add_record(
        URLReputationRecord(
            url="https://malicious.example",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"malware"},
            source="unit-test",
        )
    )

    pipeline = create_url_pipeline(service)

    result = pipeline.scan(
        "https://malicious.example"
    )

    codes = {
        finding.code
        for finding in result.findings
    }

    assert result.verdict == Verdict.MALICIOUS
    assert "URL_REPUTATION_MALICIOUS" in codes


def test_factory_instances_are_independent():
    first_pipeline = create_url_pipeline()
    second_pipeline = create_url_pipeline()

    assert first_pipeline is not second_pipeline
    assert first_pipeline.registry is not second_pipeline.registry