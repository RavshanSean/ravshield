from pathlib import Path

import pytest

from ravshield.engines.hash_engine import calculate_sha256
from ravshield.intel.file.hashing import hash_file


def test_hash_file_returns_sha256(tmp_path: Path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("Hello RavShield!")

    result = hash_file(file_path)

    assert len(result.sha256) == 64
    assert result.sha256 == calculate_sha256(file_path)


def test_hash_file_supports_string_path(tmp_path: Path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("ravshield")

    result = hash_file(str(file_path))

    assert len(result.sha256) == 64


def test_hash_file_is_deterministic(tmp_path: Path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("same content")

    first = hash_file(file_path)
    second = hash_file(file_path)

    assert first.sha256 == second.sha256


def test_invalid_file_raises_error(tmp_path: Path):
    missing_file = tmp_path / "missing.exe"

    with pytest.raises(ValueError, match="Invalid file path."):
        hash_file(missing_file)