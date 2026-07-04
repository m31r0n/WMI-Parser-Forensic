"""Tests for the dependency-free XLSX writer."""

from __future__ import annotations

import io
import xml.dom.minidom as minidom
import zipfile

from wmi_forensics.xlsx_writer import Sheet, _clip, _col_letter, workbook_bytes


def _open(data: bytes) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BytesIO(data))


def _sheet_xml(zf: zipfile.ZipFile, n: int = 1) -> str:
    return zf.read(f"xl/worksheets/sheet{n}.xml").decode("utf-8")


class TestStructure:
    def test_is_valid_zip_with_required_parts(self):
        data = workbook_bytes([Sheet("S1", ["A"], [["x"]])])
        zf = _open(data)
        names = set(zf.namelist())
        assert "[Content_Types].xml" in names
        assert "_rels/.rels" in names
        assert "xl/workbook.xml" in names
        assert "xl/_rels/workbook.xml.rels" in names
        assert "xl/styles.xml" in names
        assert "xl/worksheets/sheet1.xml" in names

    def test_all_parts_are_well_formed_xml(self):
        data = workbook_bytes([
            Sheet("One", ["H1", "H2"], [["a", 1], ["b", 2]]),
            Sheet("Two", ["X"], [[None]]),
        ])
        zf = _open(data)
        for name in zf.namelist():
            if name.endswith(".xml") or name.endswith(".rels"):
                minidom.parseString(zf.read(name))  # raises on malformed XML

    def test_multiple_sheets(self):
        data = workbook_bytes([
            Sheet("Alpha", ["A"], [["1"]]),
            Sheet("Beta", ["B"], [["2"]]),
        ])
        zf = _open(data)
        assert "xl/worksheets/sheet2.xml" in zf.namelist()
        wb = zf.read("xl/workbook.xml").decode()
        assert "Alpha" in wb and "Beta" in wb


class TestValues:
    def test_string_value_preserved(self):
        data = workbook_bytes([Sheet("S", ["Col"], [["hello world"]])])
        assert "hello world" in _sheet_xml(_open(data))

    def test_number_is_numeric_cell(self):
        data = workbook_bytes([Sheet("S", ["N"], [[42]])])
        xml = _sheet_xml(_open(data))
        assert "<v>42</v>" in xml

    def test_long_value_not_truncated_below_limit(self):
        big = "A" * 5000
        data = workbook_bytes([Sheet("S", ["B"], [[big]])])
        assert big in _sheet_xml(_open(data))

    def test_xml_special_chars_escaped(self):
        data = workbook_bytes([Sheet("S", ["C"], [["<a> & </b>"]])])
        xml = _sheet_xml(_open(data))
        assert "&lt;a&gt; &amp; &lt;/b&gt;" in xml
        minidom.parseString(xml)

    def test_control_chars_do_not_break_xml(self):
        data = workbook_bytes([Sheet("S", ["C"], [["ok\x00\x01\x07bad"]])])
        xml = _sheet_xml(_open(data))
        minidom.parseString(xml)
        assert "ok" in xml and "bad" in xml


class TestHelpers:
    def test_col_letter(self):
        assert _col_letter(0) == "A"
        assert _col_letter(25) == "Z"
        assert _col_letter(26) == "AA"
        assert _col_letter(27) == "AB"

    def test_clip_caps_at_excel_limit(self):
        clipped = _clip("Z" * 40_000)
        assert len(clipped) <= 32_767
        assert "truncated" in clipped

    def test_clip_leaves_short_values(self):
        assert _clip("short") == "short"
