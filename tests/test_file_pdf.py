from pathlib import Path

import pytest

from ravshield.intel.file.pdf import has_pdf_signature


def test_file_with_pdf_signature_is_detected(tmp_path: Path):
    file_path = tmp_path / "sample.pdf"
    file_path.write_bytes(b"%PDF-1.7\n")

    assert has_pdf_signature(file_path) is True


def test_file_without_pdf_signature_is_rejected(tmp_path: Path):
    file_path = tmp_path / "fake.pdf"
    file_path.write_bytes(b"NOT A PDF FILE")

    assert has_pdf_signature(file_path) is False


def test_pdf_signature_does_not_depend_on_extension(tmp_path: Path):
    file_path = tmp_path / "sample.txt"
    file_path.write_bytes(b"%PDF-1.7\n")

    assert has_pdf_signature(file_path) is True


def test_missing_pdf_file_raises_value_error(tmp_path: Path):
    file_path = tmp_path / "missing.pdf"

    with pytest.raises(ValueError, match="Invalid file path"):
        has_pdf_signature(file_path)


def test_truncated_pdf_signature_is_rejected(tmp_path: Path):
    file_path = tmp_path / "truncated.pdf"
    file_path.write_bytes(b"%PDF")

    assert has_pdf_signature(file_path) is False
    
from ravshield.intel.file.pdf import get_pdf_version


@pytest.mark.parametrize(
    "version",
    ["1.0", "1.4", "1.7", "2.0"],
)
def test_get_pdf_version_reads_valid_header(
    tmp_path: Path,
    version: str,
):
    file_path = tmp_path / "sample.pdf"
    file_path.write_bytes(f"%PDF-{version}\n".encode("ascii"))

    assert get_pdf_version(file_path) == version


@pytest.mark.parametrize(
    "header",
    [
        b"NOT A PDF",
        b"%PDF-",
        b"%PDF-1.",
        b"%PDF-3.0",
        b"%PDF-1.A",
        b"%PDF-1-7",
    ],
)
def test_get_pdf_version_rejects_invalid_header(
    tmp_path: Path,
    header: bytes,
):
    file_path = tmp_path / "invalid.pdf"
    file_path.write_bytes(header)

    with pytest.raises(ValueError, match="Invalid PDF version header"):
        get_pdf_version(file_path)


def test_get_pdf_version_rejects_missing_file(tmp_path: Path):
    file_path = tmp_path / "missing.pdf"

    with pytest.raises(ValueError, match="Invalid file path"):
        get_pdf_version(file_path)
        
from ravshield.intel.file.pdf import has_pdf_eof_marker


def test_pdf_eof_marker_is_detected(tmp_path: Path):
    file_path = tmp_path / "valid.pdf"
    file_path.write_bytes(b"%PDF-1.7\n%%EOF\n")

    assert has_pdf_eof_marker(file_path) is True


def test_pdf_without_eof_marker_is_rejected(tmp_path: Path):
    file_path = tmp_path / "missing_eof.pdf"
    file_path.write_bytes(b"%PDF-1.7\nSome PDF data")

    assert has_pdf_eof_marker(file_path) is False


def test_pdf_eof_marker_with_trailing_whitespace(tmp_path: Path):
    file_path = tmp_path / "trailing.pdf"
    file_path.write_bytes(b"%PDF-1.7\n%%EOF\n\n   ")

    assert has_pdf_eof_marker(file_path) is True


def test_pdf_eof_marker_outside_last_1024_bytes(tmp_path: Path):
    file_path = tmp_path / "distant_eof.pdf"
    file_path.write_bytes(b"%PDF-1.7\n%%EOF" + b"X" * 2048)

    assert has_pdf_eof_marker(file_path) is False


def test_missing_pdf_file_eof_raises_value_error(tmp_path: Path):
    file_path = tmp_path / "missing.pdf"

    with pytest.raises(ValueError, match="Invalid file path"):
        has_pdf_eof_marker(file_path)
        
from ravshield.intel.file.pdf import has_pdf_javascript


@pytest.mark.parametrize(
    "content",
    [
        b"%PDF-1.7\n/JavaScript\n%%EOF",
        b"%PDF-1.7\n/JS (app.alert('Hello'))\n%%EOF",
        b"%PDF-1.7\n/S /JavaScript\n/JS (test)\n%%EOF",
    ],
)
def test_pdf_javascript_detected(tmp_path: Path, content: bytes):
    file_path = tmp_path / "javascript.pdf"
    file_path.write_bytes(content)

    assert has_pdf_javascript(file_path) is True


@pytest.mark.parametrize(
    "content",
    [
        b"%PDF-1.7\n/Type /Catalog\n%%EOF",
        b"%PDF-1.7\n/JavaScriptAction\n%%EOF",
        b"%PDF-1.7\n/JSCode\n%%EOF",
        b"%PDF-1.7\nThis document contains JavaScript\n%%EOF",
    ],
)
def test_pdf_javascript_not_detected(tmp_path: Path, content: bytes):
    file_path = tmp_path / "safe.pdf"
    file_path.write_bytes(content)

    assert has_pdf_javascript(file_path) is False


def test_pdf_javascript_missing_file(tmp_path: Path):
    file_path = tmp_path / "missing.pdf"

    with pytest.raises(ValueError, match="Invalid file path"):
        has_pdf_javascript(file_path)
        
from ravshield.intel.file.pdf import has_pdf_dangerous_actions


@pytest.mark.parametrize(
    "content",
    [
        b"%PDF-1.7\n/OpenAction 5 0 R\n%%EOF",
        b"%PDF-1.7\n/S /Launch\n%%EOF",
        b"%PDF-1.7\n/AA << /O 3 0 R >>\n%%EOF",
        b"%PDF-1.7\n/OpenAction /Launch\n%%EOF",
    ],
)
def test_pdf_dangerous_actions_detected(tmp_path: Path, content: bytes):
    file_path = tmp_path / "dangerous.pdf"
    file_path.write_bytes(content)

    assert has_pdf_dangerous_actions(file_path) is True


@pytest.mark.parametrize(
    "content",
    [
        b"%PDF-1.7\n/Type /Catalog\n%%EOF",
        b"%PDF-1.7\n/OpenActionHandler\n%%EOF",
        b"%PDF-1.7\n/Launcher\n%%EOF",
        b"%PDF-1.7\n/AAHandler\n%%EOF",
        b"%PDF-1.7\nThis document mentions OpenAction\n%%EOF",
    ],
)
def test_pdf_dangerous_actions_not_detected(tmp_path: Path, content: bytes):
    file_path = tmp_path / "normal.pdf"
    file_path.write_bytes(content)

    assert has_pdf_dangerous_actions(file_path) is False


def test_pdf_dangerous_actions_missing_file(tmp_path: Path):
    file_path = tmp_path / "missing.pdf"

    with pytest.raises(ValueError, match="Invalid file path"):
        has_pdf_dangerous_actions(file_path)
        
from ravshield.intel.file.pdf import has_pdf_embedded_files


@pytest.mark.parametrize(
    "content",
    [
        b"%PDF-1.7\n/Type /EmbeddedFile\n%%EOF",
        b"%PDF-1.7\n/Names << /EmbeddedFiles 5 0 R >>\n%%EOF",
        b"%PDF-1.7\n/EmbeddedFile\n%%EOF",
        b"%PDF-1.7\n/EmbeddedFiles\n%%EOF",
    ],
)
def test_pdf_embedded_files_detected(tmp_path: Path, content: bytes):
    file_path = tmp_path / "embedded.pdf"
    file_path.write_bytes(content)

    assert has_pdf_embedded_files(file_path) is True


@pytest.mark.parametrize(
    "content",
    [
        b"%PDF-1.7\n/Type /Catalog\n%%EOF",
        b"%PDF-1.7\n/EmbeddedFileHandler\n%%EOF",
        b"%PDF-1.7\n/EmbeddedFilesList\n%%EOF",
        b"%PDF-1.7\nThis document mentions EmbeddedFile\n%%EOF",
        b"%PDF-1.7\n%%EOF",
    ],
)
def test_pdf_embedded_files_not_detected(tmp_path: Path, content: bytes):
    file_path = tmp_path / "normal.pdf"
    file_path.write_bytes(content)

    assert has_pdf_embedded_files(file_path) is False


def test_pdf_embedded_files_missing_file(tmp_path: Path):
    file_path = tmp_path / "missing.pdf"

    with pytest.raises(ValueError, match="Invalid file path"):
        has_pdf_embedded_files(file_path)