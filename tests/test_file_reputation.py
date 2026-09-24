from pathlib import Path

from ravshield.engines.hash_engine import calculate_sha256
from ravshield.enums import Severity
from ravshield.intel.file.reputation import check_file_reputation
from ravshield.intel.ioc import IOC
from ravshield.intel.store import IOCStore


def test_unknown_file_returns_none(tmp_path: Path):
    file_path = tmp_path / "unknown.bin"
    file_path.write_text("unknown file")

    store = IOCStore()

    result = check_file_reputation(
        file_path,
        store,
    )

    assert result is None


def test_known_malicious_file_matches_ioc(tmp_path: Path):
    file_path = tmp_path / "malware.bin"
    file_path.write_text("known malicious sample")

    sha256 = calculate_sha256(file_path)

    store = IOCStore()
    store.add(
        IOC(
            value=sha256,
            indicator_type="sha256",
            severity=Severity.CRITICAL,
            source="test-intelligence",
            confidence=99,
        )
    )

    result = check_file_reputation(
        file_path,
        store,
    )

    assert result is not None
    assert result.code == "ioc_match"
    assert result.severity == Severity.CRITICAL
    assert result.confidence == 99
    assert result.evidence["indicator_type"] == "sha256"
    assert result.evidence["value"] == sha256
    assert result.evidence["source"] == "test-intelligence"