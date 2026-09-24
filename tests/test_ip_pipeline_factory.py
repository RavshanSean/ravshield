from ravshield.analyzers import create_ip_pipeline
from ravshield.enums import Severity, Verdict
from ravshield.intel.ip import (
    IPReputationRecord,
    IPReputationService,
)


def test_factory_registers_ip_analyzers():
    pipeline = create_ip_pipeline()

    result = pipeline.scan("8.8.8.8")

    assert result.analysis_modules == [
        "ip_reputation",
        "ip_heuristics",
    ]


def test_factory_detects_suspicious_ip():
    pipeline = create_ip_pipeline()

    result = pipeline.scan("127.0.0.1")

    codes = {
        finding.code
        for finding in result.findings
    }

    assert "IP_LOOPBACK" in codes


def test_factory_detects_known_malicious_ip():
    service = IPReputationService()

    service.add_record(
        IPReputationRecord(
            ip="203.0.113.10",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"botnet"},
            source="unit-test",
        )
    )

    pipeline = create_ip_pipeline(service)

    result = pipeline.scan("203.0.113.10")

    codes = {
        finding.code
        for finding in result.findings
    }

    assert result.verdict == Verdict.MALICIOUS
    assert "IP_REPUTATION_MALICIOUS" in codes


def test_reputation_and_heuristics_combine():
    service = IPReputationService()

    service.add_record(
        IPReputationRecord(
            ip="127.0.0.1",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"malicious"},
            source="unit-test",
        )
    )

    pipeline = create_ip_pipeline(service)

    result = pipeline.scan("127.0.0.1")

    codes = {
        finding.code
        for finding in result.findings
    }

    assert "IP_REPUTATION_MALICIOUS" in codes
    assert "IP_LOOPBACK" in codes
    assert result.analysis_modules == [
        "ip_reputation",
        "ip_heuristics",
    ]


def test_factory_instances_are_independent():
    first_pipeline = create_ip_pipeline()
    second_pipeline = create_ip_pipeline()

    assert first_pipeline is not second_pipeline
    assert first_pipeline.registry is not second_pipeline.registry