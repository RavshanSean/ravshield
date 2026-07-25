from ravshield.analyzers import (
    ScanPipeline,
    URLAnalyzer,
    URLHeuristicAnalyzer,
)
from ravshield.enums import Severity, Verdict
from ravshield.intel.url import (
    URLReputationRecord,
    URLReputationService,
)


def test_reputation_and_heuristics_flow_through_pipeline():
    service = URLReputationService()

    service.add_record(
        URLReputationRecord(
            url=(
                "https://user:pass@"
                "login.verify.account.example.com/%76erify"
            ),
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"phishing", "credential-theft"},
            source="unit-test",
        )
    )

    pipeline = ScanPipeline()
    pipeline.register(URLAnalyzer(service))
    pipeline.register(URLHeuristicAnalyzer())

    result = pipeline.scan(
        "https://user:pass@"
        "login.verify.account.example.com/%76erify"
    )

    codes = {finding.code for finding in result.findings}

    assert result.verdict == Verdict.MALICIOUS

    assert "URL_REPUTATION_MALICIOUS" in codes
    assert "URL_EMBEDDED_CREDENTIALS" in codes
    assert "URL_SUSPICIOUS_KEYWORDS" in codes
    assert "URL_EXCESSIVE_SUBDOMAINS" in codes
    assert "URL_ENCODED_CHARACTERS" in codes

    assert "url_reputation" in result.analysis_modules
    assert "url_heuristics" in result.analysis_modules

    assert len(result.findings) >= 5


def test_unknown_suspicious_url_is_detected_by_heuristics():
    pipeline = ScanPipeline()
    pipeline.register(URLAnalyzer())
    pipeline.register(URLHeuristicAnalyzer())

    result = pipeline.scan(
        "https://user:pass@"
        "login.verify.account.unknown-example.com/%76erify"
    )

    codes = {finding.code for finding in result.findings}

    assert "URL_REPUTATION_MALICIOUS" not in codes
    assert "URL_REPUTATION_KNOWN" not in codes

    assert "URL_EMBEDDED_CREDENTIALS" in codes
    assert "URL_SUSPICIOUS_KEYWORDS" in codes
    assert "URL_EXCESSIVE_SUBDOMAINS" in codes
    assert "URL_ENCODED_CHARACTERS" in codes

    assert len(result.findings) >= 4


def test_clean_unknown_url_produces_no_findings():
    pipeline = ScanPipeline()
    pipeline.register(URLAnalyzer())
    pipeline.register(URLHeuristicAnalyzer())

    result = pipeline.scan(
        "https://example.com/products"
    )

    assert result.findings == []

    assert result.analysis_modules == [
        "url_reputation",
        "url_heuristics",
    ]