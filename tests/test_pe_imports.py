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
