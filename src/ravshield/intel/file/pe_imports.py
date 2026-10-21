from __future__ import annotations

from ravshield.intel.file.pe_sections import parse_pe_sections

from pathlib import Path

from ravshield.intel.file.validator import validate_file

from ravshield.intel.file.pe_models import (
    PEHeader,
    PESection,
    PEDataDirectory,
    PEImportDescriptor,
)

# PE header helpers are imported inside get_import_directory.

def get_import_directory(
    file_path: str | Path,
) -> PEDataDirectory:
    """
    Read the import data directory from a PE file.
    """
    from ravshield.intel.file.pe import (
        parse_pe_header,
        get_optional_header_magic,
        PE32_MAGIC,
        PE32_PLUS_MAGIC,
        PE32_DATA_DIRECTORY_OFFSET,
        PE32_PLUS_DATA_DIRECTORY_OFFSET,
        IMPORT_DIRECTORY_INDEX,
        DATA_DIRECTORY_SIZE,
        COFF_HEADER_SIZE,
    )

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()
    file_size = path.stat().st_size

    header = parse_pe_header(path)
    magic = get_optional_header_magic(path)

    directory_start = (
        PE32_DATA_DIRECTORY_OFFSET
        if magic == PE32_MAGIC
        else PE32_PLUS_DATA_DIRECTORY_OFFSET
    )

    directory_end = (
        directory_start
        + (IMPORT_DIRECTORY_INDEX + 1) * DATA_DIRECTORY_SIZE
    )

    if header.size_of_optional_header < directory_end:
        raise ValueError(
            "PE Optional Header is too small for import directory."
        )

    with path.open("rb") as file:
        file.seek(0x3C)
        pe_offset = int.from_bytes(
            file.read(4),
            byteorder="little",
        )

        optional_header_offset = (
            pe_offset + 4 + COFF_HEADER_SIZE
        )

        if (
            optional_header_offset > file_size
            or header.size_of_optional_header
            > file_size - optional_header_offset
        ):
            raise ValueError(
                "Truncated PE Optional Header."
            )

        file.seek(
            optional_header_offset
            + directory_start
            + IMPORT_DIRECTORY_INDEX * DATA_DIRECTORY_SIZE
        )

        raw_directory = file.read(DATA_DIRECTORY_SIZE)

    if len(raw_directory) != DATA_DIRECTORY_SIZE:
        raise ValueError("Truncated PE import directory.")

    return PEDataDirectory(
        rva=int.from_bytes(raw_directory[0:4], "little"),
        size=int.from_bytes(raw_directory[4:8], "little"),
    )
    
def rva_to_file_offset(
    file_path: str | Path,
    rva: int,
) -> int:
    """
    Translate a PE RVA into a raw file offset.
    """

    if not isinstance(rva, int) or isinstance(rva, bool) or rva < 0:
        raise ValueError("RVA must be a non-negative integer.")

    sections = parse_pe_sections(file_path)
    file_size = Path(file_path).expanduser().stat().st_size

    for section in sections:
        start = section.virtual_address
        raw_size = section.raw_data_size

        if start <= rva < start + raw_size:
            relative_offset = rva - start
            file_offset = section.raw_data_pointer + relative_offset

            if file_offset >= file_size:
                raise ValueError("RVA points outside file bounds.")

            return file_offset

    raise ValueError("RVA is not mapped to raw section data.")

def parse_import_descriptors(
    file_path: str | Path,
) -> list[PEImportDescriptor]:
    """
    Parse PE import directory descriptors.
    """

    import_directory = get_import_directory(file_path)

    if import_directory.rva == 0 or import_directory.size == 0:
        return []

    file_path = Path(file_path).expanduser()
    file_size = file_path.stat().st_size

    descriptor_offset = rva_to_file_offset(
        file_path,
        import_directory.rva,
    )

    descriptor_size = 20

    if import_directory.size < descriptor_size:
        raise ValueError("Import directory is too small.")

    if import_directory.size % descriptor_size != 0:
        raise ValueError("Import directory has an invalid size.")

    max_descriptors = min(
        import_directory.size // descriptor_size,
        4096,
    )

    sections = parse_pe_sections(file_path)

    matching_section = next(
        (
            section
            for section in sections
            if section.virtual_address <= import_directory.rva
            < section.virtual_address + section.raw_data_size
        ),
        None,
    )

    if matching_section is None:
        raise ValueError("Import directory is not mapped to a section.")

    section_end = (
        matching_section.raw_data_pointer
        + matching_section.raw_data_size
    )

    directory_end = descriptor_offset + import_directory.size

    if directory_end > section_end or directory_end > file_size:
        raise ValueError("Import directory exceeds section or file bounds.")

    descriptors = []
    found_terminator = False

    with file_path.open("rb") as file:
        for index in range(max_descriptors):
            offset = descriptor_offset + index * descriptor_size

            if offset + descriptor_size > file_size:
                raise ValueError("Import descriptor exceeds file bounds.")

            file.seek(offset)
            data = file.read(descriptor_size)

            if len(data) != descriptor_size:
                raise ValueError("Truncated PE import descriptor.")

            values = [
                int.from_bytes(data[i:i + 4], "little")
                for i in range(0, descriptor_size, 4)
            ]

            if all(value == 0 for value in values):
                found_terminator = True
                break

            descriptors.append(
                PEImportDescriptor(
                    original_first_thunk=values[0],
                    time_date_stamp=values[1],
                    forwarder_chain=values[2],
                    name_rva=values[3],
                    first_thunk=values[4],
                )
            )
            
    if not found_terminator:
        raise ValueError("Import directory has no null terminator.")

    return descriptors

def read_pe_string(
    file_path: str | Path,
    rva: int,
    max_length: int = 256,
) -> str:
    """
    Read a null-terminated ASCII string from a PE RVA.
    """

    if not isinstance(max_length, int) or isinstance(max_length, bool):
        raise ValueError("max_length must be a positive integer.")

    if max_length <= 0 or max_length > 4096:
        raise ValueError("max_length must be between 1 and 4096.")

    file_path = Path(file_path).expanduser()
    file_size = file_path.stat().st_size

    offset = rva_to_file_offset(file_path, rva)

    sections = parse_pe_sections(file_path)

    matching_section = next(
        (
            section
            for section in sections
            if section.virtual_address <= rva
            < section.virtual_address + section.raw_data_size
        ),
        None,
    )

    if matching_section is None:
        raise ValueError("String RVA is not mapped to a section.")

    section_end = (
        matching_section.raw_data_pointer
        + matching_section.raw_data_size
    )

    available_bytes = min(
        max_length,
        section_end - offset,
        file_size - offset,
    )

    with file_path.open("rb") as file:
        file.seek(offset)
        data = file.read(available_bytes)

    null_position = data.find(b"\x00")

    if null_position == -1:
        raise ValueError("PE string is not null-terminated.")

    try:
        return data[:null_position].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("PE string contains non-ASCII bytes.") from exc