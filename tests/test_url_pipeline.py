from ravshield.analyzers import ScanPipeline, URLAnalyzer
from ravshield.enums import Severity, Verdict
from ravshield.intel.url import (
    URLReputationRecord,
    URLReputationService,
)


def test_malicious_url_flows_through_pipeline():
    service = URLReputationService()

    service.add_record(
        URLReputationRecord(
            url="https://evil.example",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"phishing", "credential-theft"},
            source="unit-test",
        )
    )

    pipeline = ScanPipeline()
    pipeline.register(URLAnalyzer(service))

    result = pipeline.scan(
        "https://evil.example"
    )

    assert result.verdict == Verdict.MALICIOUS
    assert result.severity == Severity.HIGH
    assert result.findings[0].severity == Severity.CRITICAL 
    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.code == "URL_REPUTATION_MALICIOUS"
    assert finding.confidence == 99
    assert "url_reputation" in result.analysis_modules


def test_unknown_url_flows_through_pipeline():
    pipeline = ScanPipeline()
    pipeline.register(URLAnalyzer())

    result = pipeline.scan(
        "https://unknown.example"
    )

    assert result.findings == []
    assert "url_reputation" in result.analysis_modules


def test_analyze_and_scan_return_same_result():
    pipeline = ScanPipeline()
    pipeline.register(URLAnalyzer())

    analyze_result = pipeline.analyze(
        "https://unknown.example"
    )

    scan_result = pipeline.scan(
        "https://unknown.example"
    )

    assert analyze_result == scan_result