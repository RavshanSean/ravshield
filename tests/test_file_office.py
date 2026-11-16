from __future__ import annotations

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

import ravshield.intel.file.office as office_module
from ravshield.intel.file.office import OfficeAnalysisResult, analyze_office


@pytest.fixture
def make_office(tmp_path: Path):
    def create(entries: dict[str, bytes], name: str = "sample.docx") -> Path:
        path = tmp_path / name
        with ZipFile(path, "w", compression=ZIP_DEFLATED) as archive:
            for filename, content in entries.items():
                archive.writestr(filename, content)
        return path

    return create


@pytest.mark.parametrize(
    ("main_part", "expected_type"),
    [
        ("word/document.xml", "docx"),
        ("xl/workbook.xml", "xlsx"),
        ("ppt/presentation.xml", "pptx"),
    ],
)
def test_recognizes_ooxml_types(make_office, main_part, expected_type):
    path = make_office({"[Content_Types].xml": b"<Types/>", main_part: b"<root/>"})
    result = analyze_office(path)
    assert isinstance(result, OfficeAnalysisResult)
    assert result.file_type == expected_type
    assert result.is_ooxml is True
    assert result.entry_count == 2
    assert result.warnings == ()


def test_extension_does_not_determine_type(make_office):
    path = make_office(
        {"[Content_Types].xml": b"<Types/>", "xl/workbook.xml": b"<root/>"},
        name="renamed.docx",
    )
    assert analyze_office(path).file_type == "xlsx"


def test_missing_content_types_is_not_recognized_ooxml(make_office):
    path = make_office({"word/document.xml": b"<document/>"})
    result = analyze_office(path)
    assert result.file_type == "docx"
    assert result.is_ooxml is False
    assert any("Not a recognized OOXML" in warning for warning in result.warnings)


def test_unrelated_zip_is_not_ooxml(make_office):
    path = make_office({"notes.txt": b"hello"})
    result = analyze_office(path)
    assert result.file_type is None
    assert result.is_ooxml is False
    assert result.entry_count == 1


def test_detects_vba_project(make_office):
    path = make_office(
        {
            "[Content_Types].xml": b"<Types/>",
            "word/document.xml": b"<document/>",
            "word/vbaProject.bin": b"dummy",
        }
    )
    assert analyze_office(path).has_macros is True


def test_does_not_confuse_macro_filename(make_office):
    path = make_office({"word/vbaProject.bin.backup": b"dummy"})
    assert analyze_office(path).has_macros is False


@pytest.mark.parametrize("embedded_name", ["word/embeddings/oleObject1.bin", "embeddings/file.bin"])
def test_detects_embedded_objects(make_office, embedded_name):
    path = make_office({embedded_name: b"data"})
    assert analyze_office(path).has_embedded_objects is True


def test_does_not_confuse_embedding_prefix(make_office):
    path = make_office({"word/embeddings_backup/file.bin": b"data"})
    assert analyze_office(path).has_embedded_objects is False


@pytest.mark.parametrize(
    "relationship_xml",
    [
        b'<Relationships><Relationship TargetMode="External" Target="https://example.org"/></Relationships>',
        b"<Relationship TargetMode='External' Target='https://example.org'/>",
        b'<Relationship TargetMode = "external" Target="https://example.org"/>',
    ],
)
def test_detects_external_relationships(make_office, relationship_xml):
    path = make_office({"word/_rels/document.xml.rels": relationship_xml})
    assert analyze_office(path).has_external_relationships is True


def test_internal_relationship_is_not_external(make_office):
    path = make_office({"word/_rels/document.xml.rels": b'<Relationship TargetMode="Internal"/>'})
    assert analyze_office(path).has_external_relationships is False


def test_oversized_relationship_is_skipped_with_warning(make_office, monkeypatch):
    monkeypatch.setattr(office_module, "MAX_RELATIONSHIP_BYTES", 10)
    path = make_office({"word/_rels/document.xml.rels": b'<Relationship TargetMode="External"/>'})
    result = analyze_office(path)
    assert result.has_external_relationships is False
    assert "Relationship part exceeds scan limit." in result.warnings


def test_file_size_limit(make_office, monkeypatch):
    path = make_office({"notes.txt": b"some data"})
    monkeypatch.setattr(office_module, "MAX_OFFICE_FILE_SIZE", 1)
    with pytest.raises(ValueError, match="Office file exceeds maximum scan size"):
        analyze_office(path)


def test_entry_count_limit(make_office, monkeypatch):
    path = make_office({"a.txt": b"a", "b.txt": b"b"})
    monkeypatch.setattr(office_module, "MAX_OFFICE_ENTRIES", 1)
    with pytest.raises(ValueError, match="Office archive has too many entries"):
        analyze_office(path)


def test_uncompressed_size_limit(make_office, monkeypatch):
    path = make_office({"data.txt": b"a" * 100})
    monkeypatch.setattr(office_module, "MAX_OFFICE_UNCOMPRESSED_SIZE", 50)
    with pytest.raises(ValueError, match="Office archive exceeds uncompressed size limit"):
        analyze_office(path)


def test_missing_file_raises_value_error(tmp_path: Path):
    with pytest.raises(ValueError, match="Invalid file path"):
        analyze_office(tmp_path / "missing.docx")


def test_invalid_zip_raises_value_error(tmp_path: Path):
    path = tmp_path / "broken.docx"
    path.write_bytes(b"not a ZIP archive")
    with pytest.raises(ValueError, match="Invalid Office ZIP container"):
        analyze_office(path)


def test_empty_zip_has_no_findings(make_office):
    path = make_office({})
    result = analyze_office(path)
    assert result.entry_count == 0
    assert result.has_macros is False
    assert result.has_embedded_objects is False
    assert result.has_external_relationships is False
    assert result.encrypted is False
