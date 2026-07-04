"""Tests for the CCM_RecentlyUsedApps (RUA) carver."""

from __future__ import annotations

import struct
from datetime import datetime
from pathlib import Path

import io
import zipfile

from wmi_forensics.ccm_rua import (
    carve_ccm_rua,
    render_rua_text,
    render_rua_xlsx,
)

_GUID_VISTA = (
    "7C261551B264D35E30A7FA29C75283DAE04BBA71DBE8F5E553F7AD381B406DD8"
    .encode("utf-16-le")
)

# Field order of the null-delimited body (matches ccm_rua._NULL_FIELDS).
_VALUES = [
    "",                              # additional_product_codes
    "Evil Corp",                     # company_name
    "evil.exe",                      # explorer_file_name
    "Evil Tool",                     # file_description
    "aaaa",                          # file_properties_hash
    "1.0.0.0",                       # file_version
    "C:\\Windows\\Temp",             # folder_path
    "20210102030405.000000+000",     # last_used_time
    "VICTIM\\admin",                 # last_user_name
    "",                              # msi_display_name
    "",                              # msi_publisher
    "",                              # msi_version
    "evil_orig.exe",                 # original_file_name
    "1033",                          # product_language
    "EvilProduct",                   # product_name
    "2.0",                           # product_version
    "bbbb",                          # software_properties_hash
]


def _filetime_ticks(dt: datetime) -> int:
    return int((dt - datetime(1601, 1, 1)).total_seconds() * 10_000_000)


def _body() -> bytes:
    fields = b"\x00\x00".join(v.encode("latin-1") for v in _VALUES)
    return b"CCM_RecentlyUsedApps\x00\x00" + fields + b"\x00\x00"


def _header(file_size: int = 12345, launch_count: int = 7) -> bytes:
    ts1 = struct.pack("<Q", _filetime_ticks(datetime(2021, 1, 2, 3, 4, 5)))
    ts2 = struct.pack("<Q", 0)
    return (
        ts1 + ts2
        + b"\x00" * 34
        + struct.pack("<L", file_size)
        + b"\x00" * 20
        + struct.pack("<L", launch_count)
    )


def _write(tmp_path: Path, payload: bytes) -> Path:
    od = tmp_path / "OBJECTS.DATA"
    od.write_bytes(b"\x00" * 64 + payload + b"\x00" * 64)
    return od


class TestFullRecord:
    def test_full_record_parsed(self, tmp_path):
        od = _write(tmp_path, _GUID_VISTA + _header() + _body())
        records = carve_ccm_rua(od)
        assert len(records) == 1
        r = records[0]
        assert r.explorer_file_name == "evil.exe"
        assert r.folder_path == "C:\\Windows\\Temp"
        assert r.last_user_name == "VICTIM\\admin"
        assert r.original_file_name == "evil_orig.exe"

    def test_header_fields(self, tmp_path):
        od = _write(tmp_path, _GUID_VISTA + _header(file_size=999, launch_count=42) + _body())
        r = carve_ccm_rua(od)[0]
        assert r.record_format == "vista_full"
        assert r.file_size == 999
        assert r.launch_count == 42
        assert r.timestamp_1.startswith("2021-01-02 03:04:05")

    def test_last_used_time_normalised(self, tmp_path):
        od = _write(tmp_path, _GUID_VISTA + _header() + _body())
        r = carve_ccm_rua(od)[0]
        assert r.last_used_time == "2021-01-02 03:04:05"
        assert r.time_zone_offset == "+000"


class TestCarvedRecord:
    def test_body_without_header(self, tmp_path):
        od = _write(tmp_path, _body())
        records = carve_ccm_rua(od)
        assert len(records) == 1
        r = records[0]
        assert r.record_format == "carved"
        assert r.launch_count is None
        assert r.timestamp_1 == ""
        assert r.explorer_file_name == "evil.exe"


class TestXmlRecord:
    def test_xml_record_parsed(self, tmp_path):
        xml = (
            "<CCM_RecentlyUsedApps><AdditionalProductCodes></AdditionalProductCodes>"
            "<CompanyName>Contoso</CompanyName><ExplorerFileName>app.exe</ExplorerFileName>"
            "<FileDescription>App</FileDescription><FilePropertiesHash>h1</FilePropertiesHash>"
            "<FileSize>4096</FileSize><FileVersion>3.1</FileVersion>"
            "<FolderPath>C:\\Program Files\\App</FolderPath>"
            "<LastUsedTime>20200510121314.000000+000</LastUsedTime>"
            "<LastUserName>CORP\\bob</LastUserName><msiDisplayName></msiDisplayName>"
            "<msiPublisher></msiPublisher><msiVersion></msiVersion>"
            "<OriginalFileName>app_orig.exe</OriginalFileName><ProductCode>{GUID}</ProductCode>"
            "<ProductLanguage>1033</ProductLanguage><ProductName>AppProduct</ProductName>"
            "<ProductVersion>3.0</ProductVersion><SoftwarePropertiesHash>h2</SoftwarePropertiesHash>"
            "</CCM_RecentlyUsedApps>"
        )
        od = _write(tmp_path, xml.encode("latin-1"))
        records = carve_ccm_rua(od)
        assert len(records) == 1
        r = records[0]
        assert r.record_format == "xml"
        assert r.explorer_file_name == "app.exe"
        assert r.file_size == 4096
        assert r.product_code == "{GUID}"
        assert r.last_used_time == "2020-05-10 12:13:14"


class TestNoiseAndEmpty:
    def test_schema_definition_rejected(self, tmp_path):
        # The class definition matches the body regex but field values are the
        # property names themselves — must be filtered out.
        schema_fields = [
            "AdditionalProductCodes", "CompanyName", "ExplorerFileName",
            "FileDescription", "FilePropertiesHash", "FileVersion", "FolderPath",
            "LastUsedTime", "LastUserName", "msiDisplayName", "msiPublisher",
            "msiVersion", "OriginalFileName", "ProductLanguage", "ProductName",
            "ProductVersion", "SoftwarePropertiesHash",
        ]
        body = b"CCM_RecentlyUsedApps\x00\x00" + b"\x00\x00".join(
            v.encode() for v in schema_fields
        ) + b"\x00\x00"
        od = _write(tmp_path, body)
        assert carve_ccm_rua(od) == []

    def test_empty_file(self, tmp_path):
        od = tmp_path / "OBJECTS.DATA"
        od.write_bytes(b"\x00" * 1000)
        assert carve_ccm_rua(od) == []


class TestRendering:
    def test_text_and_xlsx(self, tmp_path):
        od = _write(tmp_path, _GUID_VISTA + _header() + _body())
        records = carve_ccm_rua(od)

        text = render_rua_text(od, records)
        assert "CCM RecentlyUsedApps" in text
        assert "evil.exe" in text

        data = render_rua_xlsx(od, records)
        zf = zipfile.ZipFile(io.BytesIO(data))
        assert "xl/worksheets/sheet1.xml" in zf.namelist()  # Summary
        sheet = zf.read("xl/worksheets/sheet2.xml").decode("utf-8")  # records
        assert "evil.exe" in sheet
        assert "vista_full" in sheet

    def test_empty_render(self, tmp_path):
        od = tmp_path / "OBJECTS.DATA"
        od.write_bytes(b"\x00" * 100)
        text = render_rua_text(od, [])
        assert "No CCM_RecentlyUsedApps records found" in text
