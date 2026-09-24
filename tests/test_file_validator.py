from pathlib import Path

from ravshield.intel.file.validator import validate_file


def test_existing_file_is_valid(tmp_path: Path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("ravshield")

    assert validate_file(file_path) is True


def test_missing_file_is_invalid(tmp_path: Path):
    file_path = tmp_path / "missing.txt"

    assert validate_file(file_path) is False


def test_directory_is_invalid(tmp_path: Path):
    assert validate_file(tmp_path) is False


def test_string_path_is_supported(tmp_path: Path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("ravshield")

    assert validate_file(str(file_path)) is True


def test_invalid_type_is_rejected():
    assert validate_file(123) is False