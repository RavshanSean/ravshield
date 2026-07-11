from pathlib import Path

from ravshield.engines.hash_engine import calculate_sha256


def test_calculate_sha256(tmp_path: Path):
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("Hello RavShield!")

    sha256 = calculate_sha256(sample_file)

    assert len(sha256) == 64
    assert isinstance(sha256, str)
    
