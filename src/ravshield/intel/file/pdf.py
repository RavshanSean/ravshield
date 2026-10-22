from __future__ import annotations

from pathlib import Path

from ravshield.intel.file.validator import validate_file


PDF_SIGNATURE = b"%PDF-"


def has_pdf_signature(file_path: str | Path) -> bool:
    """
    Check whether a file starts with a PDF signature.

    A valid signature alone does not prove that
    the PDF is structurally valid or safe.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    with path.open("rb") as file:
        signature = file.read(len(PDF_SIGNATURE))

    return signature == PDF_SIGNATURE

def get_pdf_version(file_path: str | Path) -> str:
    """
    Read the PDF version from its header.

    This does not validate the entire PDF structure.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    with path.open("rb") as file:
        header = file.read(8)

    if (
        len(header) != 8
        or not header.startswith(PDF_SIGNATURE)
        or header[5:6] not in (b"1", b"2")
        or header[6:7] != b"."
        or not header[7:8].isdigit()
    ):
        raise ValueError("Invalid PDF version header.")

    return header[5:8].decode("ascii")

def has_pdf_eof_marker(file_path: str | Path) -> bool:
    """
    Check whether a PDF EOF marker exists near the end of the file.

    This does not validate the entire PDF structure.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    with path.open("rb") as file:
        file.seek(0, 2)
        file_size = file.tell()

        read_size = min(file_size, 1024)
        file.seek(-read_size, 2)
        tail = file.read(read_size)

    return b"%%EOF" in tail

import re


PDF_JS_NAME_PATTERN = re.compile(
    rb"/(?:JavaScript|JS)(?![A-Za-z0-9_])"
)


def has_pdf_javascript(file_path: str | Path) -> bool:
    """
    Detect possible JavaScript-related PDF names.

    This is a heuristic scan, not full PDF parsing.
    JavaScript is never executed.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    with path.open("rb") as file:
        data = file.read()

    return PDF_JS_NAME_PATTERN.search(data) is not None

PDF_DANGEROUS_ACTION_PATTERN = re.compile(
    rb"/(?:OpenAction|Launch|AA)(?![A-Za-z0-9_])"
)


def has_pdf_dangerous_actions(file_path: str | Path) -> bool:
    """
    Detect potentially dangerous PDF action names.

    This is a heuristic scan, not full PDF parsing.
    No PDF actions are executed.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    with path.open("rb") as file:
        data = file.read()

    return PDF_DANGEROUS_ACTION_PATTERN.search(data) is not None

PDF_EMBEDDED_FILE_PATTERN = re.compile(
    rb"/(?:EmbeddedFile|EmbeddedFiles)(?![A-Za-z0-9_])"
)


def has_pdf_embedded_files(file_path: str | Path) -> bool:
    """
    Detect possible embedded-file indicators in a PDF.

    This is a heuristic scan, not full PDF parsing.
    Embedded files are never extracted or executed.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    with path.open("rb") as file:
        data = file.read()

    return PDF_EMBEDDED_FILE_PATTERN.search(data) is not None

PDF_URI_PATTERN = re.compile(
    rb"/URI(?=[\x00\x09\x0A\x0C\x0D\x20()<>\[\]{}/%])"
)


def has_pdf_external_links(file_path: str | Path) -> bool:
    """
    Detect possible URI entries in PDF files.

    This is a heuristic scan, not full PDF parsing.
    External links are never opened or visited.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    with path.open("rb") as file:
        data = file.read()

    return PDF_URI_PATTERN.search(data) is not None

PDF_SUBMIT_FORM_PATTERN = re.compile(
    rb"/SubmitForm(?=[\x00\x09\x0A\x0C\x0D\x20()<>\[\]{}/%])"
)


def has_pdf_submit_form(file_path: str | Path) -> bool:
    """
    Detect possible SubmitForm actions in PDF files.

    This is a heuristic scan, not full PDF parsing.
    No forms are submitted and no network requests are made.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    with path.open("rb") as file:
        data = file.read()

    return PDF_SUBMIT_FORM_PATTERN.search(data) is not None