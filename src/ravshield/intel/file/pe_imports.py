from __future__ import annotations

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