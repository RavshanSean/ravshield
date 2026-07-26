from ravshield.analyzers import IOCAnalyzer
from ravshield.enums import Severity
from ravshield.intel import IOC, IOCStore


def test_no_match():
    analyzer = IOCAnalyzer()

    findings = analyzer.analyze(
        ("domain", "example.com")
    )

    assert findings == []


def test_hash_match():
    store = IOCStore()

    store.add(
        IOC(
            value="44d88612fea8a8f36de82e1278abb02f",
            indicator_type="md5",
            severity=Severity.CRITICAL,
            source="unit-test",
            confidence=95,
        )
    )

    analyzer = IOCAnalyzer(store)

    findings = analyzer.analyze(
        (
            "md5",
            "44d88612fea8a8f36de82e1278abb02f",
        )
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.code == "ioc_match"
    assert finding.severity == Severity.CRITICAL
    assert finding.confidence == 95
    assert finding.evidence["indicator_type"] == "md5"
    assert finding.evidence["source"] == "unit-test"


def test_domain_match_is_normalized():
    store = IOCStore()

    store.add(
        IOC(
            value="evil.com",
            indicator_type="domain",
            severity=Severity.HIGH,
            source="unit-test",
            confidence=90,
        )
    )

    analyzer = IOCAnalyzer(store)

    findings = analyzer.analyze(
        ("domain", "EVIL.COM.")
    )

    assert len(findings) == 1
    assert findings[0].evidence["value"] == "evil.com"


def test_multiple_indicators_can_be_analyzed():
    store = IOCStore()

    store.add(
        IOC(
            value="evil.com",
            indicator_type="domain",
            severity=Severity.HIGH,
            source="unit-test",
            confidence=90,
        )
    )

    store.add(
        IOC(
            value="1.2.3.4",
            indicator_type="ip",
            severity=Severity.CRITICAL,
            source="unit-test",
            confidence=99,
        )
    )

    analyzer = IOCAnalyzer(store)

    findings = []

    findings.extend(
        analyzer.analyze(
            ("domain", "evil.com")
        )
    )

    findings.extend(
        analyzer.analyze(
            ("ip", "1.2.3.4")
        )
    )

    assert len(findings) == 2