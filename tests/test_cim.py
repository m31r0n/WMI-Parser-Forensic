"""Tests for the best-effort structured CIM class-definition decoder."""

from __future__ import annotations

import io
import struct
import zipfile
from datetime import datetime
from pathlib import Path

import base64
import zlib

from wmi_forensics.cim import find_payload_classes, parse_class_views
from wmi_forensics.class_carver import (
    carve_class_structured,
    hunt_payload_classes,
    render_hunt_text,
    render_structured_text,
    render_structured_xlsx,
)

_CLASS = "Win32_MemoryArrayDevice"
_BASE64 = "7Vp9cFzVdT" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop0123456789+/" * 4


def _filetime(dt: datetime) -> bytes:
    ticks = int((dt - datetime(1601, 1, 1)).total_seconds() * 10_000_000)
    return struct.pack("<Q", ticks)


def _string(text: str) -> bytes:
    return b"\x00" + text.encode("ascii") + b"\x00"


def _property_struct(cim_type: int, index: int, offset: int, level: int) -> bytes:
    return bytes([cim_type, 0x00, 0x00, 0x00]) + struct.pack("<HII", index, offset, level)


def _synthetic_region() -> bytes:
    # Mirror the real layout: a header carrying the FILETIME, then a DataRegion
    # (uint32 size with top bit set) holding the class name, property name,
    # property struct, and the STRING default value.
    data_region = b"".join([
        _string(_CLASS),
        _string("Property"),
        _property_struct(0x08, 0, 0, 0),   # CIM_TYPE_STRING
        b"\x11\x00\x00\x00\x0a\x00\x00\x80\x03\x08\x00\x00\x00",  # a qualifiers blob
        _string(_BASE64),
    ])
    header = b"\x00" * 8 + _filetime(datetime(2022, 6, 24, 8, 52, 38)) + b"\x05\x00\x00\x00" * 4
    size_prefix = struct.pack("<I", len(data_region) | 0x80000000)
    return header + size_prefix + data_region


def _write(tmp_path: Path, payload: bytes) -> Path:
    od = tmp_path / "OBJECTS.DATA"
    od.write_bytes(b"\x00" * 64 + payload + b"\x00" * 64)
    return od


class TestParse:
    def test_recovers_class_name(self):
        views = parse_class_views(_synthetic_region(), _CLASS)
        assert len(views) == 1
        assert views[0].class_name == _CLASS

    def test_recovers_timestamp(self):
        v = parse_class_views(_synthetic_region(), _CLASS)[0]
        assert v.timestamp.startswith("2022-06-24")

    def test_recovers_string_property(self):
        v = parse_class_views(_synthetic_region(), _CLASS)[0]
        types = {p.cim_type for p in v.properties}
        assert "CIM_TYPE_STRING" in types
        names = {p.name for p in v.properties}
        assert "Property" in names

    def test_recovers_full_default_value(self):
        v = parse_class_views(_synthetic_region(), _CLASS)[0]
        assert _BASE64 in v.default_values  # full, untruncated

    def test_no_structure_returns_empty(self):
        # A bare keyword with no surrounding structures must not fabricate a view.
        assert parse_class_views(b"prefix Win32_Nothing suffix", "Win32_Nothing") == []


class TestCarveIntegration:
    def test_structured_carve_and_renderers(self, tmp_path):
        od = _write(tmp_path, _synthetic_region())
        views = carve_class_structured(od, _CLASS)
        assert views and views[0].class_name == _CLASS

        text = render_structured_text(od, _CLASS, views)
        assert "classname: Win32_MemoryArrayDevice" in text
        assert _BASE64 in text  # untruncated in text report

        data = render_structured_xlsx(od, _CLASS, views)
        zf = zipfile.ZipFile(io.BytesIO(data))
        # sheet1=Summary, sheet4=Default Values
        values_sheet = zf.read("xl/worksheets/sheet4.xml").decode("utf-8")
        assert _BASE64 in values_sheet


def _raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def _payload_region(payload_b64: str) -> bytes:
    data_region = b"".join([
        _string(_CLASS),
        _string("Property"),
        _property_struct(0x08, 0, 0, 0),
        b"\x11\x00\x00\x00\x0a\x00\x00\x80\x03\x08\x00\x00\x00",
        _string(payload_b64),
    ])
    header = b"\x00" * 8 + _filetime(datetime(2022, 6, 24, 8, 52, 38)) + b"\x05\x00\x00\x00" * 4
    return header + struct.pack("<I", len(data_region) | 0x80000000) + data_region


class TestHunt:
    def _dotnet_b64(self) -> str:
        raw = b"MZ\x90\x00" + bytes((i * 37 + 11) % 256 for i in range(400)) + b"BSJB"
        return base64.b64encode(_raw_deflate(raw)).decode()

    def test_discovers_class_payload(self, tmp_path):
        od = _write(tmp_path, _payload_region(self._dotnet_b64()))
        hits = find_payload_classes(od.read_bytes())
        assert len(hits) == 1
        h = hits[0]
        assert h.class_name == _CLASS
        assert h.property_name == "Property"
        assert h.payload.file_type == ".net-assembly"
        assert h.payload.steps == ["base64", "raw-inflate"]

    def test_hunt_cli_helper_and_render(self, tmp_path):
        od = _write(tmp_path, _payload_region(self._dotnet_b64()))
        hits = hunt_payload_classes(od)
        text = render_hunt_text(od, hits)
        assert "Win32_MemoryArrayDevice.Property" in text
        assert ".net-assembly" in text
        assert "MITRE T1546.003" in text

    def test_no_payload_no_hits(self, tmp_path):
        od = _write(tmp_path, _payload_region(_BASE64))  # opaque, not a real file
        assert find_payload_classes(od.read_bytes()) == []
