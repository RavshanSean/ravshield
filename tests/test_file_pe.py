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
    get_import_directory,
    rva_to_file_offset,
    PEImportDescriptor,
    parse_import_descriptors,
    read_pe_string,
    get_imported_dll_names,
    get_import_thunk_rvas,
    get_imported_api_names,
    analyze_pe_imports,
    analyze_pe,
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
    
@pytest.mark.parametrize(
    "magic,optional_size,directory_offset",
    [
        (0x10B, 224, 104),  # PE32
        (0x20B, 240, 120),  # PE32+
    ],
)
def test_get_import_directory_reads_rva_and_size(
    tmp_path: Path,
    magic: int,
    optional_size: int,
    directory_offset: int,
):
    file_path = tmp_path / "imports.exe"
    data = bytearray(512)

    # DOS and PE headers
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    # COFF SizeOfOptionalHeader
    data[84:86] = optional_size.to_bytes(2, "little")

    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        magic.to_bytes(2, "little")
    )

    # Import directory entry
    entry_offset = optional_offset + directory_offset

    data[entry_offset:entry_offset + 4] = (
        0x3000
    ).to_bytes(4, "little")

    data[entry_offset + 4:entry_offset + 8] = (
        128
    ).to_bytes(4, "little")

    file_path.write_bytes(data)

    directory = get_import_directory(file_path)

    assert directory.rva == 0x3000
    assert directory.size == 128


def test_get_import_directory_rejects_truncated_optional_header(
    tmp_path: Path,
):
    file_path = tmp_path / "truncated.exe"
    data = bytearray(128)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    # Claims 224 optional-header bytes, but file is too short.
    data[84:86] = (224).to_bytes(2, "little")
    data[88:90] = (0x10B).to_bytes(2, "little")

    file_path.write_bytes(data)

    with pytest.raises(
        ValueError,
        match="Truncated PE Optional Header",
    ):
        get_import_directory(file_path)
        

@pytest.mark.parametrize(
    "rva,expected_offset",
    [
        (0x3000, 0x200),
        (0x3020, 0x220),
        (0x30FF, 0x2FF),
    ],
)
def test_rva_to_file_offset(
    tmp_path: Path,
    rva: int,
    expected_offset: int,
):
    file_path = tmp_path / "rva.exe"
    data = bytearray(1024)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    # One section, no Optional Header.
    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = (0).to_bytes(2, "little")

    # Section header begins at offset 88.
    section_offset = 88

    data[section_offset:section_offset + 8] = b".text\x00\x00\x00"
    data[section_offset + 8:section_offset + 12] = (
        0x100
    ).to_bytes(4, "little")
    data[section_offset + 12:section_offset + 16] = (
        0x3000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        0x100
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    file_path.write_bytes(data)

    assert rva_to_file_offset(file_path, rva) == expected_offset


@pytest.mark.parametrize("invalid_rva", [-1, "3000", True])
def test_rva_to_file_offset_rejects_invalid_input(
    tmp_path: Path,
    invalid_rva,
):
    file_path = tmp_path / "invalid.exe"
    file_path.write_bytes(b"MZ")

    with pytest.raises(
        ValueError,
        match="RVA must be a non-negative integer",
    ):
        rva_to_file_offset(file_path, invalid_rva)


def test_rva_to_file_offset_rejects_unmapped_rva(
    tmp_path: Path,
):
    file_path = tmp_path / "unmapped.exe"
    data = bytearray(256)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    file_path.write_bytes(data)

    with pytest.raises(
        ValueError,
        match="RVA is not mapped",
    ):
        rva_to_file_offset(file_path, 0x9000)
        

def test_parse_import_descriptors(tmp_path: Path):
    file_path = tmp_path / "imports.exe"
    data = bytearray(1024)

    # DOS and PE headers.
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    # COFF header: one section, 224-byte optional header.
    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = (224).to_bytes(2, "little")

    # PE32 optional header.
    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        0x10B
    ).to_bytes(2, "little")

    # NumberOfRvaAndSizes = 16.
    data[optional_offset + 92:optional_offset + 96] = (
        16
    ).to_bytes(4, "little")

    # Import directory: RVA 0x3000, size 40.
    import_offset = optional_offset + 96 + 8
    data[import_offset:import_offset + 4] = (
        0x3000
    ).to_bytes(4, "little")
    data[import_offset + 4:import_offset + 8] = (
        40
    ).to_bytes(4, "little")

    # Section header.
    section_offset = optional_offset + 224
    data[section_offset:section_offset + 8] = b".idata\x00\x00"
    data[section_offset + 8:section_offset + 12] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 12:section_offset + 16] = (
        0x3000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    # First import descriptor.
    fields = [0x3050, 0, 0, 0x3080, 0x3060]

    for index, value in enumerate(fields):
        start = 0x200 + index * 4
        data[start:start + 4] = value.to_bytes(4, "little")

    # Remaining 20 bytes are the null terminator.
    file_path.write_bytes(data)

    descriptors = parse_import_descriptors(file_path)

    assert len(descriptors) == 1
    assert isinstance(descriptors[0], PEImportDescriptor)
    assert descriptors[0].name_rva == 0x3080
    assert descriptors[0].first_thunk == 0x3060


def test_parse_import_descriptors_rejects_invalid_rva(
    tmp_path: Path,
):
    file_path = tmp_path / "invalid_import.exe"
    data = bytearray(512)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    data[84:86] = (224).to_bytes(2, "little")

    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        0x10B
    ).to_bytes(2, "little")

    # Import directory points to an unmapped RVA.
    import_offset = optional_offset + 96 + 8
    data[import_offset:import_offset + 4] = (
        0x9000
    ).to_bytes(4, "little")
    data[import_offset + 4:import_offset + 8] = (
        40
    ).to_bytes(4, "little")

    file_path.write_bytes(data)

    with pytest.raises(ValueError, match="RVA is not mapped"):
        parse_import_descriptors(file_path)


def test_parse_import_descriptors_empty_directory(
    tmp_path: Path,
):
    file_path = tmp_path / "empty_import.exe"
    data = bytearray(512)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"
    data[84:86] = (224).to_bytes(2, "little")

    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        0x10B
    ).to_bytes(2, "little")

    file_path.write_bytes(data)

    assert parse_import_descriptors(file_path) == []


def test_import_directory_rejects_invalid_size(
    tmp_path: Path,
):
    file_path = tmp_path / "invalid_size.exe"
    data = bytearray(1024)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = (224).to_bytes(2, "little")

    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        0x10B
    ).to_bytes(2, "little")

    import_offset = optional_offset + 96 + 8
    data[import_offset:import_offset + 4] = (
        0x3000
    ).to_bytes(4, "little")

    # Invalid size: not divisible by 20.
    data[import_offset + 4:import_offset + 8] = (
        21
    ).to_bytes(4, "little")

    section_offset = optional_offset + 224
    data[section_offset:section_offset + 8] = b".idata\x00\x00"
    data[section_offset + 12:section_offset + 16] = (
        0x3000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    file_path.write_bytes(data)

    with pytest.raises(ValueError, match="invalid size"):
        parse_import_descriptors(file_path)


def test_import_directory_rejects_missing_terminator(
    tmp_path: Path,
):
    file_path = tmp_path / "missing_terminator.exe"
    data = bytearray(1024)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = (224).to_bytes(2, "little")

    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        0x10B
    ).to_bytes(2, "little")

    import_offset = optional_offset + 96 + 8
    data[import_offset:import_offset + 4] = (
        0x3000
    ).to_bytes(4, "little")
    data[import_offset + 4:import_offset + 8] = (
        20
    ).to_bytes(4, "little")

    section_offset = optional_offset + 224
    data[section_offset:section_offset + 8] = b".idata\x00\x00"
    data[section_offset + 12:section_offset + 16] = (
        0x3000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    # Non-zero descriptor without a null terminator.
    data[0x200:0x204] = (0x3050).to_bytes(4, "little")

    file_path.write_bytes(data)

    with pytest.raises(ValueError, match="no null terminator"):
        parse_import_descriptors(file_path)


def test_get_imported_dll_names(tmp_path: Path):
    file_path = tmp_path / "dll_imports.exe"
    data = bytearray(1024)

    # DOS and PE headers.
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    # One section and PE32 optional header.
    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = (224).to_bytes(2, "little")

    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        0x10B
    ).to_bytes(2, "little")

    # Import directory: RVA 0x3000, size 40.
    import_offset = optional_offset + 96 + 8
    data[import_offset:import_offset + 4] = (
        0x3000
    ).to_bytes(4, "little")
    data[import_offset + 4:import_offset + 8] = (
        40
    ).to_bytes(4, "little")

    # Section header.
    section_offset = optional_offset + 224
    data[section_offset:section_offset + 8] = b".idata\x00\x00"

    data[section_offset + 8:section_offset + 12] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 12:section_offset + 16] = (
        0x3000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    # Import descriptor: Name RVA = 0x3080.
    data[0x200 + 12:0x200 + 16] = (
        0x3080
    ).to_bytes(4, "little")

    # DLL name at file offset 0x280.
    data[0x280:0x280 + len(b"KERNEL32.dll\x00")] = (
        b"KERNEL32.dll\x00"
    )

    file_path.write_bytes(data)

    assert get_imported_dll_names(file_path) == ["KERNEL32.dll"]
    assert read_pe_string(file_path, 0x3080) == "KERNEL32.dll"


def test_read_pe_string_rejects_invalid_length(
    tmp_path: Path,
):
    file_path = tmp_path / "invalid_length.exe"

    with pytest.raises(ValueError, match="max_length"):
        read_pe_string(file_path, 0x3000, max_length=0)

    with pytest.raises(ValueError, match="max_length"):
        read_pe_string(file_path, 0x3000, max_length=5000)


def test_get_imported_dll_names_empty_directory(
    tmp_path: Path,
):
    file_path = tmp_path / "empty_dll_imports.exe"
    data = bytearray(512)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"
    data[84:86] = (224).to_bytes(2, "little")

    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        0x10B
    ).to_bytes(2, "little")

    file_path.write_bytes(data)

    assert get_imported_dll_names(file_path) == []


@pytest.mark.parametrize(
    "string_data,error_message",
    [
        (b"\xff\x00", "non-ASCII"),
        (b"A" * 256, "not null-terminated"),
    ],
)
def test_read_pe_string_rejects_invalid_strings(
    tmp_path: Path,
    string_data: bytes,
    error_message: str,
):
    file_path = tmp_path / "invalid_dll_string.exe"
    data = bytearray(1024)

    # DOS and PE headers.
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    # One section, no optional header.
    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = (0).to_bytes(2, "little")

    # Section header starts at offset 88.
    section_offset = 88

    data[section_offset:section_offset + 8] = b".idata\x00\x00"

    data[section_offset + 8:section_offset + 12] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 12:section_offset + 16] = (
        0x3000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    # Write test string at RVA 0x3000.
    data[0x200:0x200 + len(string_data)] = string_data

    file_path.write_bytes(data)

    with pytest.raises(ValueError, match=error_message):
        read_pe_string(file_path, 0x3000)


def test_read_pe_string_rejects_section_boundary(
    tmp_path: Path,
):
    file_path = tmp_path / "boundary_string.exe"
    data = bytearray(1024)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = (0).to_bytes(2, "little")

    section_offset = 88

    data[section_offset:section_offset + 8] = b".idata\x00\x00"
    data[section_offset + 8:section_offset + 12] = (
        0x10
    ).to_bytes(4, "little")
    data[section_offset + 12:section_offset + 16] = (
        0x3000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        0x10
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    # Fill the entire section without a null terminator.
    data[0x200:0x210] = b"A" * 16

    # Null byte exists outside the section, but must not be read.
    data[0x210] = 0

    file_path.write_bytes(data)

    with pytest.raises(ValueError, match="not null-terminated"):
        read_pe_string(file_path, 0x3000)


def test_import_directory_rejects_section_overflow(
    tmp_path: Path,
):
    file_path = tmp_path / "section_overflow.exe"
    data = bytearray(1024)

    # DOS and PE headers.
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    # One section and PE32 optional header.
    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = (224).to_bytes(2, "little")

    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        0x10B
    ).to_bytes(2, "little")

    # Import directory: RVA 0x3000, size 40 bytes.
    import_offset = optional_offset + 96 + 8
    data[import_offset:import_offset + 4] = (
        0x3000
    ).to_bytes(4, "little")
    data[import_offset + 4:import_offset + 8] = (
        40
    ).to_bytes(4, "little")

    # Section contains only 20 raw bytes.
    section_offset = optional_offset + 224
    data[section_offset:section_offset + 8] = b".idata\x00\x00"

    data[section_offset + 8:section_offset + 12] = (
        0x20
    ).to_bytes(4, "little")
    data[section_offset + 12:section_offset + 16] = (
        0x3000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        20
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    file_path.write_bytes(data)

    with pytest.raises(
        ValueError,
        match="Import directory exceeds section or file bounds",
    ):
        parse_import_descriptors(file_path)


@pytest.mark.parametrize(
    "magic,optional_size,entry_size",
    [
        (0x10B, 224, 4),  # PE32
        (0x20B, 240, 8),  # PE32+
    ],
)
def test_get_import_thunk_rvas(
    tmp_path: Path,
    magic: int,
    optional_size: int,
    entry_size: int,
):
    file_path = tmp_path / "thunks.exe"
    data = bytearray(1024)

    # DOS and PE headers.
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    # One section.
    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = optional_size.to_bytes(2, "little")

    # Optional header.
    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        magic.to_bytes(2, "little")
    )

    # Section header.
    section_offset = optional_offset + optional_size
    data[section_offset:section_offset + 8] = b".idata\x00\x00"

    data[section_offset + 8:section_offset + 12] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 12:section_offset + 16] = (
        0x3000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    # Import thunk table at RVA 0x3040.
    thunk_offset = 0x240

    values = [0x3080, 0x30A0, 0]

    for index, value in enumerate(values):
        start = thunk_offset + index * entry_size
        data[start:start + entry_size] = value.to_bytes(
            entry_size,
            "little",
        )

    file_path.write_bytes(data)

    descriptor = PEImportDescriptor(
        original_first_thunk=0x3040,
        time_date_stamp=0,
        forwarder_chain=0,
        name_rva=0x30C0,
        first_thunk=0,
    )

    assert get_import_thunk_rvas(
        file_path,
        descriptor,
    ) == [0x3080, 0x30A0]


def test_get_import_thunk_rvas_rejects_invalid_limit(
    tmp_path: Path,
):
    file_path = tmp_path / "invalid_limit.exe"

    descriptor = PEImportDescriptor(
        original_first_thunk=0,
        time_date_stamp=0,
        forwarder_chain=0,
        name_rva=0,
        first_thunk=0,
    )

    for invalid_limit in (0, -1, 4097, True):
        with pytest.raises(ValueError, match="max_imports"):
            get_import_thunk_rvas(
                file_path,
                descriptor,
                max_imports=invalid_limit,
            )


@pytest.mark.parametrize(
    "raw_size,thunk_values,error_message",
    [
        (
            4,
            [0x3080],
            "Import thunk exceeds section bounds",
        ),
        (
            12,
            [0x3080, 0x30A0, 0x30C0],
            "Import thunk exceeds section bounds",
        ),
    ],
)
def test_import_thunk_rejects_section_overflow(
    tmp_path: Path,
    raw_size: int,
    thunk_values: list[int],
    error_message: str,
):
    file_path = tmp_path / "invalid_thunks.exe"
    data = bytearray(1024)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = (224).to_bytes(2, "little")

    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        0x10B
    ).to_bytes(2, "little")

    section_offset = optional_offset + 224
    data[section_offset:section_offset + 8] = b".idata\x00\x00"

    data[section_offset + 8:section_offset + 12] = (
        raw_size
    ).to_bytes(4, "little")
    data[section_offset + 12:section_offset + 16] = (
        0x3000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        raw_size
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    for index, value in enumerate(thunk_values):
        start = 0x200 + index * 4
        data[start:start + 4] = value.to_bytes(4, "little")

    file_path.write_bytes(data)

    descriptor = PEImportDescriptor(
        original_first_thunk=0x3000,
        time_date_stamp=0,
        forwarder_chain=0,
        name_rva=0,
        first_thunk=0,
    )

    with pytest.raises(ValueError, match=error_message):
        get_import_thunk_rvas(file_path, descriptor)


def test_import_thunk_rejects_missing_terminator_at_limit(
    tmp_path: Path,
):
    file_path = tmp_path / "thunk_limit.exe"
    data = bytearray(1024)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = (224).to_bytes(2, "little")

    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        0x10B
    ).to_bytes(2, "little")

    section_offset = optional_offset + 224
    data[section_offset:section_offset + 8] = b".idata\x00\x00"

    data[section_offset + 8:section_offset + 12] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 12:section_offset + 16] = (
        0x3000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    # Two non-zero entries, but max_imports allows only two.
    data[0x200:0x204] = (0x3080).to_bytes(4, "little")
    data[0x204:0x208] = (0x30A0).to_bytes(4, "little")

    file_path.write_bytes(data)

    descriptor = PEImportDescriptor(
        original_first_thunk=0x3000,
        time_date_stamp=0,
        forwarder_chain=0,
        name_rva=0,
        first_thunk=0,
    )

    with pytest.raises(ValueError, match="no null terminator"):
        get_import_thunk_rvas(
            file_path,
            descriptor,
            max_imports=2,
        )


@pytest.mark.parametrize(
    "magic,optional_size,entry_size",
    [
        (0x10B, 224, 4),
        (0x20B, 240, 8),
    ],
)
def test_get_imported_api_names(
    tmp_path: Path,
    magic: int,
    optional_size: int,
    entry_size: int,
):
    file_path = tmp_path / "api_imports.exe"
    data = bytearray(1024)

    # DOS and PE headers.
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    # COFF header.
    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = optional_size.to_bytes(2, "little")

    # Optional header.
    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        magic.to_bytes(2, "little")
    )

    # .idata section.
    section_offset = optional_offset + optional_size
    data[section_offset:section_offset + 8] = b".idata\x00\x00"

    data[section_offset + 8:section_offset + 12] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 12:section_offset + 16] = (
        0x3000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    # Import thunk table at RVA 0x3040.
    ordinal_flag = 1 << (entry_size * 8 - 1)

    thunk_values = [
        0x3080,
        0x30A0,
        ordinal_flag | 123,
        0,
    ]

    for index, value in enumerate(thunk_values):
        start = 0x240 + index * entry_size
        data[start:start + entry_size] = value.to_bytes(
            entry_size,
            "little",
        )

    # IMAGE_IMPORT_BY_NAME: 2-byte hint + API name + null.
    data[0x280:0x282] = (0).to_bytes(2, "little")
    data[0x282:0x28F] = b"VirtualAlloc\x00"

    data[0x2A0:0x2A2] = (0).to_bytes(2, "little")
    data[0x2A2:0x2AE] = b"CreateFileW\x00"

    file_path.write_bytes(data)

    descriptor = PEImportDescriptor(
        original_first_thunk=0x3040,
        time_date_stamp=0,
        forwarder_chain=0,
        name_rva=0,
        first_thunk=0,
    )

    assert get_imported_api_names(
        file_path,
        descriptor,
    ) == [
        "VirtualAlloc",
        "CreateFileW",
        "#123",
    ]


@pytest.mark.parametrize(
    "api_rva,ordinal_value,error_message",
    [
        (0, None, "Invalid ordinal import"),
        (0x5000, None, "RVA"),
        (None, 0x80010001, "Invalid ordinal import"),
        (None, 0x80000000, "Invalid ordinal import"),
    ],
)
def test_imported_api_rejects_invalid_entries(
    tmp_path: Path,
    api_rva: int | None,
    ordinal_value: int | None,
    error_message: str,
):
    file_path = tmp_path / "invalid_api.exe"
    data = bytearray(1024)

    # DOS and PE headers.
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    # COFF header: one section, PE32 optional header.
    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = (224).to_bytes(2, "little")

    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        0x10B
    ).to_bytes(2, "little")

    # .idata section.
    section_offset = optional_offset + 224
    data[section_offset:section_offset + 8] = b".idata\x00\x00"

    data[section_offset + 8:section_offset + 12] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 12:section_offset + 16] = (
        0x3000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    # Thunk table at RVA 0x3040.
    thunk_value = (
        ordinal_value
        if ordinal_value is not None
        else api_rva
    )

    # The first test case uses a nonzero thunk so it
    # reaches API-name validation rather than ending
    # the thunk table.
    if thunk_value == 0:
        thunk_value = 0x80000000

    data[0x240:0x244] = thunk_value.to_bytes(4, "little")
    data[0x244:0x248] = (0).to_bytes(4, "little")

    file_path.write_bytes(data)

    descriptor = PEImportDescriptor(
        original_first_thunk=0x3040,
        time_date_stamp=0,
        forwarder_chain=0,
        name_rva=0,
        first_thunk=0,
    )

    with pytest.raises(ValueError, match=error_message):
        get_imported_api_names(file_path, descriptor)


def test_analyze_pe_imports_combines_dlls_and_apis(
    tmp_path: Path,
):
    file_path = tmp_path / "imports.exe"
    data = bytearray(1024)

    # DOS and PE headers.
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    # COFF header.
    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = (224).to_bytes(2, "little")

    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        0x10B
    ).to_bytes(2, "little")

    # Number of RVA and Sizes.
    data[optional_offset + 92:optional_offset + 96] = (
        16
    ).to_bytes(4, "little")

    # Import directory: RVA 0x3000, size 40.
    directory_offset = optional_offset + 96 + 8
    data[directory_offset:directory_offset + 4] = (
        0x3000
    ).to_bytes(4, "little")
    data[directory_offset + 4:directory_offset + 8] = (
        40
    ).to_bytes(4, "little")

    # .idata section.
    section_offset = optional_offset + 224
    data[section_offset:section_offset + 8] = b".idata\x00\x00"

    data[section_offset + 8:section_offset + 12] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 12:section_offset + 16] = (
        0x3000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    # Import descriptor at RVA 0x3000.
    # OriginalFirstThunk = 0x3040.
    data[0x200:0x204] = (0x3040).to_bytes(4, "little")

    # Name RVA = 0x30C0.
    data[0x20C:0x210] = (0x30C0).to_bytes(4, "little")

    # FirstThunk = 0x3040.
    data[0x210:0x214] = (0x3040).to_bytes(4, "little")

    # Second descriptor is all zeros (terminator).

    # Import thunk table.
    data[0x240:0x244] = (0x3080).to_bytes(4, "little")
    data[0x244:0x248] = (0x30A0).to_bytes(4, "little")
    data[0x248:0x24C] = (0).to_bytes(4, "little")

    # Imported API names: hint + name + null.
    data[0x280:0x282] = (0).to_bytes(2, "little")
    data[0x282:0x28F] = b"VirtualAlloc\x00"

    data[0x2A0:0x2A2] = (0).to_bytes(2, "little")
    data[0x2A2:0x2AE] = b"CreateFileW\x00"

    # DLL name.
    data[0x2C0:0x2CD] = b"KERNEL32.dll\x00"

    file_path.write_bytes(data)

    assert analyze_pe_imports(file_path) == {
        "KERNEL32.dll": [
            "VirtualAlloc",
            "CreateFileW",
        ],
    }
    

@pytest.mark.parametrize(
    "magic,optional_size,expected_format",
    [
        (0x10B, 224, "PE32"),
        (0x20B, 240, "PE32+"),
    ],
)
def test_analyze_pe_returns_format_and_imports(
    tmp_path: Path,
    magic: int,
    optional_size: int,
    expected_format: str,
):
    file_path = tmp_path / "analyze.exe"
    data = bytearray(1024)

    # DOS and PE signatures.
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"

    # COFF header: one section.
    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = optional_size.to_bytes(2, "little")

    # Optional header.
    optional_offset = 88
    data[optional_offset:optional_offset + 2] = (
        magic.to_bytes(2, "little")
    )

    # NumberOfRvaAndSizes = 16.
    directory_count_offset = (
        92 if magic == 0x10B else 108
    )
    data[
        optional_offset + directory_count_offset:
        optional_offset + directory_count_offset + 4
    ] = (16).to_bytes(4, "little")

    # No imports: Import Directory RVA and size are zero.

    # One .text section.
    section_offset = optional_offset + optional_size
    data[section_offset:section_offset + 8] = b".text\x00\x00\x00"

    data[section_offset + 8:section_offset + 12] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 12:section_offset + 16] = (
        0x1000
    ).to_bytes(4, "little")
    data[section_offset + 16:section_offset + 20] = (
        0x200
    ).to_bytes(4, "little")
    data[section_offset + 20:section_offset + 24] = (
        0x200
    ).to_bytes(4, "little")

    file_path.write_bytes(data)

    result = analyze_pe(file_path)

    assert result == {
        "format": expected_format,
        "imports": {},
    }

