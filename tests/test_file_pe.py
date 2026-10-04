from pathlib import Path

import pytest

from ravshield.intel.file.pe import (
    has_pe_signature,
    has_valid_pe_header,
    parse_pe_header,
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
    
def test_parse_pe_header_reads_coff_fields(
    tmp_path: Path,
):
    file_path = tmp_path / "sample.exe"

    data = bytearray(256)

    # DOS header
    data[0:2] = b"MZ"

    # PE header starts at offset 64
    data[0x3C:0x40] = (64).to_bytes(
        4,
        byteorder="little",
    )

    # PE signature
    data[64:68] = b"PE\x00\x00"

    # COFF header starts immediately after PE signature
    coff_offset = 68

    # Machine: AMD64
    data[coff_offset:coff_offset + 2] = (
        0x8664
    ).to_bytes(2, byteorder="little")

    # NumberOfSections
    data[coff_offset + 2:coff_offset + 4] = (
        3
    ).to_bytes(2, byteorder="little")

    # TimeDateStamp
    data[coff_offset + 4:coff_offset + 8] = (
        123456789
    ).to_bytes(4, byteorder="little")

    # SizeOfOptionalHeader
    data[coff_offset + 16:coff_offset + 18] = (
        240
    ).to_bytes(2, byteorder="little")

    # Characteristics
    data[coff_offset + 18:coff_offset + 20] = (
        0x0022
    ).to_bytes(2, byteorder="little")

    file_path.write_bytes(data)

    header = parse_pe_header(file_path)

    assert header.machine == 0x8664
    assert header.number_of_sections == 3
    assert header.timestamp == 123456789
    assert header.size_of_optional_header == 240
    assert header.characteristics == 0x0022
    
def test_parse_pe_header_rejects_truncated_coff_header(
    tmp_path: Path,
):
    file_path = tmp_path / "truncated.exe"

    data = bytearray(78)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(
        4,
        byteorder="little",
    )
    data[64:68] = b"PE\x00\x00"

    file_path.write_bytes(data)

    with pytest.raises(
        ValueError,
        match="Truncated PE COFF header",
    ):
        parse_pe_header(file_path)