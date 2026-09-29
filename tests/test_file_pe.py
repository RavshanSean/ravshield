from pathlib import Path

import pytest

from ravshield.intel.file.pe import has_pe_signature


def test_file_with_mz_signature_is_detected(
    tmp_path: Path,
):
    file_path = tmp_path / "sample.exe"
    file_path.write_bytes(b"MZ" + b"\x00" * 20)

    assert has_pe_signature(file_path) is True


def test_file_without_mz_signature_is_not_detected(
    tmp_path: Path,
):
    file_path = tmp_path / "sample.exe"
    file_path.write_bytes(b"NOT A PE FILE")

    assert has_pe_signature(file_path) is False


def test_extension_does_not_determine_pe_signature(
    tmp_path: Path,
):
    file_path = tmp_path / "sample.txt"
    file_path.write_bytes(b"MZ" + b"\x00" * 20)

    assert has_pe_signature(file_path) is True


def test_missing_file_raises_value_error(
    tmp_path: Path,
):
    file_path = tmp_path / "missing.exe"

    with pytest.raises(ValueError, match="Invalid file path"):
        has_pe_signature(file_path)