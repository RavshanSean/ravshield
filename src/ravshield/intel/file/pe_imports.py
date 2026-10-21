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