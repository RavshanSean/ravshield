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

    
    assert result["format"] == expected_format
    assert result["imports"] == {}

    # Validate PE header.
    assert result["header"]["number_of_sections"] == 1
    assert result["header"]["size_of_optional_header"] == optional_size

    # Validate parsed sections.
    assert len(result["sections"]) == 1

    section = result["sections"][0]

    assert section["name"] == ".text"
    assert section["virtual_address"] == 0x1000
    assert section["raw_data_size"] == 0x200
    assert section["raw_data_pointer"] == 0x200

    # The test section contains only zero bytes.
    assert section["entropy"] == 0.0

@pytest.mark.parametrize(
    "file_data",
    [
        b"",
        b"Not a PE file",
        b"MZ",
        b"MZ" + b"\x00" * 62,
    ],
)
def test_analyze_pe_rejects_invalid_files(
    tmp_path: Path,
    file_data: bytes,
):
    file_path = tmp_path / "invalid.exe"
    file_path.write_bytes(file_data)

    with pytest.raises(ValueError):
        analyze_pe(file_path)

def test_analyze_pe_rejects_missing_file(
    tmp_path: Path,
):
    file_path = tmp_path / "missing.exe"

    with pytest.raises((ValueError, FileNotFoundError)):
        analyze_pe(file_path)
