from datetime import UTC, datetime, timedelta

from ravshield.analyzers import (
    create_email_pipeline,
    create_file_pipeline,
    create_hash_pipeline,
    create_ip_pipeline,
    create_url_pipeline,
)
from ravshield.engines import MultiSignalVerdictEngine
from ravshield.enums import Severity, Verdict
from ravshield.intel import IOC, IOCStore
from ravshield.intel.email import analyze_email_auth_headers
from ravshield.intel.ip import (
    IPReputationRecord,
    IPReputationService,
)
from ravshield.intel.lifecycle import effective_confidence, is_expired
from ravshield.intel.url import (
    URLReputationRecord,
    URLReputationService,
)
from ravshield.models import DetectionFinding
from ravshield.plugins import (
    EnrichmentAnalyzer,
    StaticMapEnricher,
)
from ravshield.reputation import KNOWN_BAD_HASHES


def test_heuristics_only_cap_at_suspicious() -> None:
    engine = MultiSignalVerdictEngine()

    findings = [
        DetectionFinding(
            code="URL_EMBEDDED_CREDENTIALS",
            title="Embedded Credentials",
            description="heuristic",
            severity=Severity.HIGH,
            confidence=70,
        ),
        DetectionFinding(
            code="URL_SUSPICIOUS_KEYWORDS",
            title="Keywords",
            description="heuristic",
            severity=Severity.MEDIUM,
            confidence=70,
        ),
        DetectionFinding(
            code="URL_EXCESSIVE_SUBDOMAINS",
            title="Subdomains",
            description="heuristic",
            severity=Severity.MEDIUM,
            confidence=70,
        ),
    ]

    result = engine.analyze(findings)

    assert result.risk_score >= 70
    assert result.verdict is Verdict.SUSPICIOUS


def test_typed_reputation_malicious_is_strong() -> None:
    engine = MultiSignalVerdictEngine()

    result = engine.analyze(
        [
            DetectionFinding(
                code="URL_REPUTATION_MALICIOUS",
                title="Known malicious URL",
                description="intel",
                severity=Severity.HIGH,
                confidence=90,
            )
        ]
    )

    assert result.verdict is Verdict.MALICIOUS


def test_expired_url_reputation_is_ignored() -> None:
    service = URLReputationService()

    service.add_record(
        URLReputationRecord(
            url="https://expired.example",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
    )

    result = service.check("https://expired.example")

    assert result.known is False
    assert result.expired is True
    assert result.malicious is False


def test_source_confidence_scales_effective_confidence() -> None:
    assert effective_confidence(0.80, 0.50) == 0.40
    assert is_expired(None) is False


def test_ip_pipeline_detects_malicious_reputation() -> None:
    service = IPReputationService()

    service.add_record(
        IPReputationRecord(
            ip="203.0.113.10",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.95,
            tags={"c2"},
            source="unit-test",
        )
    )

    pipeline = create_ip_pipeline(service)
    result = pipeline.scan("203.0.113.10")

    codes = {finding.code for finding in result.findings}

    assert result.verdict is Verdict.MALICIOUS
    assert "IP_REPUTATION_MALICIOUS" in codes
    assert "ip_reputation" in result.analysis_modules
    assert "ip_heuristics" in result.analysis_modules


def test_url_pipeline_wires_ioc_store() -> None:
    store = IOCStore()
    store.add(
        IOC(
            value="https://evil.example/path",
            indicator_type="url",
            severity=Severity.HIGH,
            source="unit-test",
            confidence=90,
        )
    )

    pipeline = create_url_pipeline(ioc_store=store)
    result = pipeline.scan("https://evil.example/path")

    codes = {finding.code for finding in result.findings}

    assert result.verdict is Verdict.MALICIOUS
    assert "ioc_match" in codes


def test_email_auth_headers_detect_spf_fail() -> None:
    result = analyze_email_auth_headers(
        {
            "Authentication-Results": (
                "mx.example.com; spf=fail smtp.mailfrom=evil.test; "
                "dkim=pass header.d=evil.test; dmarc=fail action=reject"
            )
        }
    )

    assert "spf_fail" in result.signals
    assert "dmarc_fail" in result.signals
    assert result.spf == "fail"
    assert result.dmarc == "fail"


def test_email_pipeline_scans_auth_headers() -> None:
    pipeline = create_email_pipeline()

    result = pipeline.scan(
        {
            "address": "user@example.com",
            "headers": {
                "Authentication-Results": (
                    "mx.example.com; spf=fail; dkim=fail; dmarc=fail"
                )
            },
        }
    )

    codes = {finding.code for finding in result.findings}

    assert "EMAIL_SPF_FAIL" in codes
    assert "EMAIL_DKIM_FAIL" in codes
    assert "EMAIL_DMARC_FAIL" in codes
    assert result.verdict is Verdict.SUSPICIOUS


def test_static_enrichment_malicious_tag() -> None:
    enricher = StaticMapEnricher(
        "asn-map",
        {
            "198.51.100.8": {
                "asn": 64500,
                "org": "Bad Hosting",
                "tags": ["tor", "scanner"],
            }
        },
    )

    analyzer = EnrichmentAnalyzer([enricher])
    findings = analyzer.analyze(("ip", "198.51.100.8"))

    assert findings[0].code == "ENRICHMENT_MALICIOUS_TAG"

    engine = MultiSignalVerdictEngine()
    result = engine.analyze(findings)

    assert result.verdict is Verdict.MALICIOUS


def test_hash_pipeline_detects_builtin_bad_hash(
    tmp_path,
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"ravshield-malware-sample")

    from ravshield.engines.hash_engine import calculate_sha256

    digest = calculate_sha256(sample)
    KNOWN_BAD_HASHES.add(digest)

    try:
        file_result = create_file_pipeline().scan(sample)
        hash_result = create_hash_pipeline().scan(digest)

        assert file_result.verdict is Verdict.MALICIOUS
        assert hash_result.verdict is Verdict.MALICIOUS
        assert any(
            finding.code == "HASH_REPUTATION_MALICIOUS"
            for finding in file_result.findings
        )
    finally:
        KNOWN_BAD_HASHES.discard(digest)
