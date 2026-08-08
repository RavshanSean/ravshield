from ravshield.analyzers import IPHeuristicAnalyzer
from ravshield.enums import Severity


def test_public_ip_returns_no_findings():
    analyzer = IPHeuristicAnalyzer()

    findings = analyzer.analyze(
        "8.8.8.8"
    )

    assert findings == []


def test_loopback_ip_returns_findings():
    analyzer = IPHeuristicAnalyzer()

    findings = analyzer.analyze(
        "127.0.0.1"
    )

    codes = {
        finding.code
        for finding in findings
    }

    assert "IP_LOOPBACK" in codes
    assert "IP_PRIVATE_ADDRESS" in codes


def test_loopback_finding_has_high_severity():
    analyzer = IPHeuristicAnalyzer()

    findings = analyzer.analyze(
        "127.0.0.1"
    )

    finding = next(
        finding
        for finding in findings
        if finding.code == "IP_LOOPBACK"
    )

    assert finding.severity == Severity.HIGH
    assert finding.confidence == 95
    assert finding.evidence["ip"] == "127.0.0.1"


def test_private_ip_returns_medium_finding():
    analyzer = IPHeuristicAnalyzer()

    findings = analyzer.analyze(
        "192.168.1.10"
    )

    finding = next(
        finding
        for finding in findings
        if finding.code == "IP_PRIVATE_ADDRESS"
    )

    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == 90


def test_link_local_ip_returns_finding():
    analyzer = IPHeuristicAnalyzer()

    findings = analyzer.analyze(
        "169.254.10.20"
    )

    codes = {
        finding.code
        for finding in findings
    }

    assert "IP_LINK_LOCAL" in codes
    assert "IP_PRIVATE_ADDRESS" in codes


def test_multicast_ip_returns_finding():
    analyzer = IPHeuristicAnalyzer()

    findings = analyzer.analyze(
        "224.0.0.1"
    )

    codes = {
        finding.code
        for finding in findings
    }

    assert "IP_MULTICAST" in codes


def test_reserved_ip_returns_finding():
    analyzer = IPHeuristicAnalyzer()

    findings = analyzer.analyze(
        "240.0.0.1"
    )

    codes = {
        finding.code
        for finding in findings
    }

    assert "IP_RESERVED" in codes


def test_ipv6_loopback_is_supported():
    analyzer = IPHeuristicAnalyzer()

    findings = analyzer.analyze(
        "::1"
    )

    codes = {
        finding.code
        for finding in findings
    }

    assert "IP_LOOPBACK" in codes
    assert "IP_PRIVATE_ADDRESS" in codes