from pathlib import Path

import pytest

from ravshield.intel.file.pe import (
    find_suspicious_section_names,
    has_pe_signature,
    has_valid_pe_header,
    has_writable_executable_section,
    parse_pe_header,
    parse_pe_sections,
    calculate_entropy,
    calculate_section_entropies,
    find_high_entropy_sections,
    get_optional_header_magic,
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
        
def test_parse_pe_sections_reads_section_fields(
    tmp_path: Path,
):
    file_path = tmp_path / "sections.exe"

    data = bytearray(512)

    # DOS header
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(
        4,
        byteorder="little",
    )

    # PE signature
    data[64:68] = b"PE\x00\x00"

    # COFF header
    coff_offset = 68

    # AMD64
    data[coff_offset:coff_offset + 2] = (
        0x8664
    ).to_bytes(2, byteorder="little")

    # One section
    data[coff_offset + 2:coff_offset + 4] = (
        1
    ).to_bytes(2, byteorder="little")

    # No optional header in this synthetic PE
    data[coff_offset + 16:coff_offset + 18] = (
        0
    ).to_bytes(2, byteorder="little")

    # Section table begins after PE signature + COFF header
    section_offset = 88

    data[section_offset:section_offset + 8] = (
        b".text\x00\x00\x00"
    )

    data[section_offset + 8:section_offset + 12] = (
        0x1000
    ).to_bytes(4, byteorder="little")

    data[section_offset + 12:section_offset + 16] = (
        0x2000
    ).to_bytes(4, byteorder="little")

    data[section_offset + 16:section_offset + 20] = (
        0x600
    ).to_bytes(4, byteorder="little")

    data[section_offset + 20:section_offset + 24] = (
        0x400
    ).to_bytes(4, byteorder="little")

    data[section_offset + 36:section_offset + 40] = (
        0x60000020
    ).to_bytes(4, byteorder="little")

    file_path.write_bytes(data)

    sections = parse_pe_sections(file_path)

    assert len(sections) == 1

    section = sections[0]

    assert section.name == ".text"
    assert section.virtual_size == 0x1000
    assert section.virtual_address == 0x2000
    assert section.raw_data_size == 0x600
    assert section.raw_data_pointer == 0x400
    assert section.characteristics == 0x60000020
    
def test_parse_pe_sections_rejects_truncated_section_table(
    tmp_path: Path,
):
    file_path = tmp_path / "truncated_sections.exe"

    data = bytearray(100)

    # DOS header
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(
        4,
        byteorder="little",
    )

    # PE signature
    data[64:68] = b"PE\x00\x00"

    # COFF header starts at offset 68
    coff_offset = 68

    # Claim that the PE contains one section
    data[coff_offset + 2:coff_offset + 4] = (
        1
    ).to_bytes(2, byteorder="little")

    # No optional header
    data[coff_offset + 16:coff_offset + 18] = (
        0
    ).to_bytes(2, byteorder="little")

    file_path.write_bytes(data)

    with pytest.raises(
        ValueError,
        match="Truncated PE section table",
    ):
        parse_pe_sections(file_path)
        
def _create_pe_with_section_characteristics(
    tmp_path: Path,
    characteristics: int,
) -> Path:
    file_path = tmp_path / "section_flags.exe"

    data = bytearray(512)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(
        4,
        byteorder="little",
    )

    data[64:68] = b"PE\x00\x00"

    coff_offset = 68

    data[coff_offset + 2:coff_offset + 4] = (
        1
    ).to_bytes(2, byteorder="little")

    data[coff_offset + 16:coff_offset + 18] = (
        0
    ).to_bytes(2, byteorder="little")

    section_offset = 88

    data[section_offset:section_offset + 8] = (
        b".text\x00\x00\x00"
    )

    data[section_offset + 36:section_offset + 40] = (
        characteristics
    ).to_bytes(4, byteorder="little")

    file_path.write_bytes(data)

    return file_path

def test_writable_executable_section_is_detected(
    tmp_path: Path,
):
    file_path = _create_pe_with_section_characteristics(
        tmp_path,
        0xE0000020,
    )

    assert (
        has_writable_executable_section(file_path)
        is True
    )


def test_normal_executable_section_is_not_writable_executable(
    tmp_path: Path,
):
    file_path = _create_pe_with_section_characteristics(
        tmp_path,
        0x60000020,
    )

    assert (
        has_writable_executable_section(file_path)
        is False
    )
    
def test_suspicious_packer_section_name_is_detected(
    tmp_path: Path,
):
    file_path = tmp_path / "packed.exe"

    data = bytearray(512)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(
        4,
        byteorder="little",
    )

    data[64:68] = b"PE\x00\x00"

    coff_offset = 68

    data[coff_offset + 2:coff_offset + 4] = (
        1
    ).to_bytes(2, byteorder="little")

    data[coff_offset + 16:coff_offset + 18] = (
        0
    ).to_bytes(2, byteorder="little")

    section_offset = 88
    data[section_offset:section_offset + 8] = (
        b"UPX0\x00\x00\x00\x00"
    )

    file_path.write_bytes(data)

    assert find_suspicious_section_names(
        file_path
    ) == ["UPX0"]


def test_normal_section_name_is_not_suspicious(
    tmp_path: Path,
):
    file_path = tmp_path / "normal.exe"

    data = bytearray(512)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(
        4,
        byteorder="little",
    )

    data[64:68] = b"PE\x00\x00"

    coff_offset = 68

    data[coff_offset + 2:coff_offset + 4] = (
        1
    ).to_bytes(2, byteorder="little")

    data[coff_offset + 16:coff_offset + 18] = (
        0
    ).to_bytes(2, byteorder="little")

    section_offset = 88
    data[section_offset:section_offset + 8] = (
        b".text\x00\x00\x00"
    )

    file_path.write_bytes(data)

    assert find_suspicious_section_names(
        file_path
    ) == []
    
def test_empty_data_has_zero_entropy():
    assert calculate_entropy(b"") == 0.0


def test_repeated_bytes_have_zero_entropy():
    assert calculate_entropy(b"A" * 100) == 0.0


def test_varied_bytes_have_higher_entropy():
    low_entropy = calculate_entropy(
        b"A" * 256
    )

    high_entropy = calculate_entropy(
        bytes(range(256))
    )

    assert high_entropy > low_entropy
    assert high_entropy == pytest.approx(8.0)
    
def test_calculate_section_entropies_reads_raw_section_data(
    tmp_path: Path,
):
    file_path = tmp_path / "entropy.exe"

    data = bytearray(512)

    # DOS header
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(
        4,
        byteorder="little",
    )

    # PE signature
    data[64:68] = b"PE\x00\x00"

    # COFF header
    coff_offset = 68

    data[coff_offset + 2:coff_offset + 4] = (
        1
    ).to_bytes(2, byteorder="little")

    data[coff_offset + 16:coff_offset + 18] = (
        0
    ).to_bytes(2, byteorder="little")

    # Section header
    section_offset = 88

    data[section_offset:section_offset + 8] = (
        b".text\x00\x00\x00"
    )

    # Raw data size = 256 bytes
    data[section_offset + 16:section_offset + 20] = (
        256
    ).to_bytes(4, byteorder="little")

    # Raw data begins at offset 256
    data[section_offset + 20:section_offset + 24] = (
        256
    ).to_bytes(4, byteorder="little")

    # Give the section all possible byte values.
    data[256:512] = bytes(range(256))

    file_path.write_bytes(data)

    entropies = calculate_section_entropies(
        file_path
    )

    assert entropies[".text"] == pytest.approx(8.0)
    
def test_section_entropy_rejects_out_of_bounds_raw_data(
    tmp_path: Path,
):
    file_path = tmp_path / "bad_section_data.exe"

    data = bytearray(256)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(
        4,
        byteorder="little",
    )

    data[64:68] = b"PE\x00\x00"

    coff_offset = 68

    data[coff_offset + 2:coff_offset + 4] = (
        1
    ).to_bytes(2, byteorder="little")

    data[coff_offset + 16:coff_offset + 18] = (
        0
    ).to_bytes(2, byteorder="little")

    section_offset = 88

    data[section_offset:section_offset + 8] = (
        b".text\x00\x00\x00"
    )

    # Claims 100 bytes of section data...
    data[section_offset + 16:section_offset + 20] = (
        100
    ).to_bytes(4, byteorder="little")

    # ...starting at byte 220.
    # 220 + 100 exceeds the real 256-byte file.
    data[section_offset + 20:section_offset + 24] = (
        220
    ).to_bytes(4, byteorder="little")

    file_path.write_bytes(data)

    with pytest.raises(
        ValueError,
        match="PE section data exceeds file bounds",
    ):
        calculate_section_entropies(file_path)
        
def test_high_entropy_section_is_detected(
    tmp_path: Path,
):
    file_path = tmp_path / "high_entropy.exe"

    data = bytearray(512)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(
        4,
        byteorder="little",
    )

    data[64:68] = b"PE\x00\x00"

    coff_offset = 68

    data[coff_offset + 2:coff_offset + 4] = (
        1
    ).to_bytes(2, byteorder="little")

    data[coff_offset + 16:coff_offset + 18] = (
        0
    ).to_bytes(2, byteorder="little")

    section_offset = 88

    data[section_offset:section_offset + 8] = (
        b".text\x00\x00\x00"
    )

    data[section_offset + 16:section_offset + 20] = (
        256
    ).to_bytes(4, byteorder="little")

    data[section_offset + 20:section_offset + 24] = (
        256
    ).to_bytes(4, byteorder="little")

    data[256:512] = bytes(range(256))

    file_path.write_bytes(data)

    matches = find_high_entropy_sections(
        file_path
    )

    assert ".text" in matches
    assert matches[".text"] == pytest.approx(8.0)


def test_low_entropy_section_is_not_detected(
    tmp_path: Path,
):
    file_path = tmp_path / "low_entropy.exe"

    data = bytearray(512)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(
        4,
        byteorder="little",
    )

    data[64:68] = b"PE\x00\x00"

    coff_offset = 68

    data[coff_offset + 2:coff_offset + 4] = (
        1
    ).to_bytes(2, byteorder="little")

    data[coff_offset + 16:coff_offset + 18] = (
        0
    ).to_bytes(2, byteorder="little")

    section_offset = 88

    data[section_offset:section_offset + 8] = (
        b".text\x00\x00\x00"
    )

    data[section_offset + 16:section_offset + 20] = (
        256
    ).to_bytes(4, byteorder="little")

    data[section_offset + 20:section_offset + 24] = (
        256
    ).to_bytes(4, byteorder="little")

    data[256:512] = b"A" * 256

    file_path.write_bytes(data)

    assert find_high_entropy_sections(
        file_path
    ) == {}


def test_high_entropy_rejects_invalid_threshold(
    tmp_path: Path,
):
    file_path = tmp_path / "unused.exe"

    with pytest.raises(
        ValueError,
        match="Entropy threshold must be between",
    ):
        find_high_entropy_sections(
            file_path,
            threshold=9.0,
        )
        
def test_get_optional_header_magic_detects_pe32(
    tmp_path: Path,
):
    file_path = tmp_path / "pe32.exe"

    data = bytearray(256)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(
        4,
        byteorder="little",
    )

    data[64:68] = b"PE\x00\x00"

    coff_offset = 68

    # Optional Header exists.
    data[coff_offset + 16:coff_offset + 18] = (
        224
    ).to_bytes(2, byteorder="little")

    optional_header_offset = 88

    data[
        optional_header_offset:
        optional_header_offset + 2
    ] = (0x10B).to_bytes(
        2,
        byteorder="little",
    )

    file_path.write_bytes(data)

    assert get_optional_header_magic(
        file_path
    ) == 0x10B


def test_get_optional_header_magic_detects_pe32_plus(
    tmp_path: Path,
):
    file_path = tmp_path / "pe32_plus.exe"

    data = bytearray(256)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(
        4,
        byteorder="little",
    )

    data[64:68] = b"PE\x00\x00"

    coff_offset = 68

    data[coff_offset + 16:coff_offset + 18] = (
        240
    ).to_bytes(2, byteorder="little")

    optional_header_offset = 88

    data[
        optional_header_offset:
        optional_header_offset + 2
    ] = (0x20B).to_bytes(
        2,
        byteorder="little",
    )

    file_path.write_bytes(data)

    assert get_optional_header_magic(
        file_path
    ) == 0x20B


def test_get_optional_header_magic_rejects_unknown_magic(
    tmp_path: Path,
):
    file_path = tmp_path / "unknown.exe"

    data = bytearray(256)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(
        4,
        byteorder="little",
    )

    data[64:68] = b"PE\x00\x00"

    coff_offset = 68

    data[coff_offset + 16:coff_offset + 18] = (
        224
    ).to_bytes(2, byteorder="little")

    optional_header_offset = 88

    data[
        optional_header_offset:
        optional_header_offset + 2
    ] = (0x999).to_bytes(
        2,
        byteorder="little",
    )

    file_path.write_bytes(data)

    with pytest.raises(
        ValueError,
        match="Unsupported PE Optional Header magic",
    ):
        get_optional_header_magic(file_path)