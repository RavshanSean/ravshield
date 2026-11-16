"""Regression tests for the unified, read-only file analysis dispatcher."""

from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile

import pytest

from ravshield.intel.file import pipeline


def _file(tmp_path: Path, name: str, content: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


def _zip(tmp_path: Path, name: str, entries: dict[str, bytes]) -> Path:
    path = tmp_path / name
    with ZipFile(path, "w") as archive:
        for member, data in entries.items():
            archive.writestr(member, data)
    return path


def test_pdf_signature_routes_to_pdf(tmp_path, monkeypatch):
    path = _file(tmp_path, "wrong.txt", b"%PDF-1.7\n%%EOF")
    sentinel = object()
    monkeypatch.setattr(pipeline, "analyze_pdf", lambda p: sentinel)
    result = pipeline.analyze_file(path)
    assert (result.file_type, result.analyzer, result.details) == ("pdf", "pdf", sentinel)


def test_pdf_near_signature_is_unknown(tmp_path):
    result = pipeline.analyze_file(_file(tmp_path, "x.pdf", b"%PDX-1.7"))
    assert result.file_type == "unknown"
    assert result.analyzer is None


def test_pdf_empty_file_is_unknown(tmp_path):
    assert pipeline.analyze_file(_file(tmp_path, "empty.pdf", b"")).file_type == "unknown"


def test_pdf_extension_without_signature_is_unknown(tmp_path):
    assert pipeline.analyze_file(_file(tmp_path, "fake.pdf", b"hello")).file_type == "unknown"


def test_pe_signature_routes_to_pe(tmp_path, monkeypatch):
    path = _file(tmp_path, "program.txt", b"MZ" + b"\x00" * 100)
    sentinel = {"format": "PE32"}
    monkeypatch.setattr(pipeline, "analyze_pe", lambda p: sentinel)
    result = pipeline.analyze_file(path)
    assert result.file_type == "pe"
    assert result.analyzer == "pe"
    assert result.details is sentinel


@pytest.mark.parametrize("error", [ValueError("bad"), OSError("bad"), EOFError(), IndexError(), KeyError()])
def test_pe_parser_errors_are_reported(tmp_path, monkeypatch, error):
    path = _file(tmp_path, "program.exe", b"MZ")
    def fail(_):
        raise error
    monkeypatch.setattr(pipeline, "analyze_pe", fail)
    result = pipeline.analyze_file(path)
    assert result.file_type == "pe_candidate"
    assert result.analyzer == "pe"
    assert result.details is None
    assert "PE analysis incomplete" in result.warnings[0]


def test_zip_routes_to_archive(tmp_path):
    path = _zip(tmp_path, "data.zip", {"readme.txt": b"hello"})
    result = pipeline.analyze_file(path)
    assert result.file_type == "zip"
    assert result.analyzer == "archive"
    assert result.details["inspection"].filenames == ["readme.txt"]
    assert result.details["nested_archives"] == []
    assert result.details["encrypted_files"] == []


def test_empty_zip_routes_to_archive(tmp_path):
    path = _zip(tmp_path, "empty.zip", {})
    result = pipeline.analyze_file(path)
    assert result.file_type == "zip"
    assert result.details["inspection"].file_count == 0


def test_archive_reports_nested_zip(tmp_path):
    path = _zip(tmp_path, "outer.zip", {"inner.zip": b"not extracted"})
    result = pipeline.analyze_file(path)
    assert result.details["nested_archives"] == ["inner.zip"]


def test_ooxml_word_routes_to_office(tmp_path):
    path = _zip(tmp_path, "document.zip", {
        "[Content_Types].xml": b"<Types/>",
        "word/document.xml": b"<document/>",
    })
    result = pipeline.analyze_file(path)
    assert result.file_type == "docx"
    assert result.analyzer == "office"
    assert result.details.is_ooxml is True


@pytest.mark.parametrize("main_part,expected", [
    ("xl/workbook.xml", "xlsx"),
    ("ppt/presentation.xml", "pptx"),
])
def test_other_ooxml_types(tmp_path, main_part, expected):
    path = _zip(tmp_path, "document.zip", {
        "[Content_Types].xml": b"<Types/>", main_part: b"<root/>"
    })
    result = pipeline.analyze_file(path)
    assert result.file_type == expected
    assert result.analyzer == "office"


def test_ooxml_missing_content_types_routes_to_zip(tmp_path):
    path = _zip(tmp_path, "partial.docx", {"word/document.xml": b"<root/>"})
    assert pipeline.analyze_file(path).file_type == "zip"


def test_ooxml_content_types_alone_routes_to_zip(tmp_path):
    path = _zip(tmp_path, "partial.docx", {"[Content_Types].xml": b"<Types/>"})
    assert pipeline.analyze_file(path).file_type == "zip"


def test_invalid_zip_raises_value_error(tmp_path):
    path = _file(tmp_path, "bad.zip", b"PK\x03\x04broken")
    with pytest.raises(ValueError, match="ZIP"):
        pipeline.analyze_file(path)


def test_zip_dispatch_entry_limit(tmp_path, monkeypatch):
    path = _zip(tmp_path, "many.zip", {"a": b"1", "b": b"2"})
    monkeypatch.setattr(pipeline, "MAX_ZIP_DISPATCH_ENTRIES", 1)
    with pytest.raises(ValueError, match="too many entries"):
        pipeline.analyze_file(path)


def test_missing_path_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="Invalid file path"):
        pipeline.analyze_file(tmp_path / "missing.bin")


def test_directory_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="Invalid file path"):
        pipeline.analyze_file(tmp_path)


def test_unknown_file_returns_warning(tmp_path):
    result = pipeline.analyze_file(_file(tmp_path, "notes.txt", b"plain text"))
    assert result.file_type == "unknown"
    assert result.details is None
    assert "No supported file signature detected." in result.warnings
