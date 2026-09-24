from pathlib import Path

import pytest

from ravshield.intel.file.metadata import get_file_metadata


def test_collects_file_metadata(tmp_path: Path):
    file_path = tmp_path / "sample.TXT"
    file_path.write_text("ravshield")

    metadata = get_file_metadata(file_path)

    assert metadata.name == "sample.TXT"
    assert metadata.extension == ".txt"
    assert metadata.size == 9


def test_file_without_extension(tmp_path: Path):
    file_path = tmp_path / "README"
    file_path.write_text("ravshield")

    metadata = get_file_metadata(file_path)

    assert metadata.name == "README"
    assert metadata.extension == ""
    assert metadata.size == 9


def test_string_path_is_supported(tmp_path: Path):
    file_path = tmp_path / "sample.pdf"
    file_path.write_text("test")

    metadata = get_file_metadata(str(file_path))

    assert metadata.name == "sample.pdf"
    assert metadata.extension == ".pdf"
    assert metadata.size == 4


def test_invalid_file_raises_error(tmp_path: Path):
    missing_file = tmp_path / "missing.exe"

    with pytest.raises(ValueError, match="Invalid file path."):
        get_file_metadata(missing_file)