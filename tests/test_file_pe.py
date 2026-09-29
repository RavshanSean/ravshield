from pathlib import Path

import pytest

from ravshield.intel.file.pe import (
    has_pe_signature,
    has_valid_pe_header,
)


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


def test_valid_pe_header_is_detected(
    tmp_path: Path,
):
    file_path = tmp_path / "valid.exe"

    data = bytearray(128)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, byteorder="little")
    data[64:68] = b"PE\x00\x00"

    file_path.write_bytes(data)

    assert has_valid_pe_header(file_path) is True


def test_mz_without_valid_pe_header_is_rejected(
    tmp_path: Path,
):
    file_path = tmp_path / "fake.exe"

    data = bytearray(128)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, byteorder="little")
    data[64:68] = b"NOPE"

    file_path.write_bytes(data)

    assert has_valid_pe_header(file_path) is False


def test_pe_header_without_mz_is_rejected(
    tmp_path: Path,
):
    file_path = tmp_path / "fake.exe"

    data = bytearray(128)
    data[0x3C:0x40] = (64).to_bytes(4, byteorder="little")
    data[64:68] = b"PE\x00\x00"

    file_path.write_bytes(data)

    assert has_valid_pe_header(file_path) is False


def test_truncated_dos_header_is_rejected(
    tmp_path: Path,
):
    file_path = tmp_path / "tiny.exe"
    file_path.write_bytes(b"MZ")

    assert has_valid_pe_header(file_path) is False