from pathlib import Path
from ravshield.engines.hash_engine import calculate_sha256, validate_hash


def test_calculate_sha256(tmp_path: Path):
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("Hello RavShield!")

    sha256 = calculate_sha256(sample_file)

    assert len(sha256) == 64
    assert isinstance(sha256, str)
    
def test_validate_hash():
    valid_sha256 = "a" * 64
    valid_sha1 = "b" * 40
    valid_md5 = "c" * 32

    assert validate_hash(valid_sha256, "sha256") is True
    assert validate_hash(valid_sha1, "sha1") is True
    assert validate_hash(valid_md5, "md5") is True

    assert validate_hash("not-a-valid-hash", "sha256") is False
    assert validate_hash("a" * 63, "sha256") is False
    assert validate_hash("z" * 64, "sha256") is False
    assert validate_hash("a" * 64, "unknown") is False