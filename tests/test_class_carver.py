"""Tests for keyword-focused class/context carving."""

from __future__ import annotations

from pathlib import Path

from wmi_forensics.class_carver import carve_class_context, render_hits_json, render_hits_text


def test_finds_ascii_and_utf16_keyword(tmp_path: Path):
    od = tmp_path / "OBJECTS.DATA"
    payload = b"".join([
        b"random prefix\x00",
        b"Win32_MemoryArrayDevice\x00\x00",
        b"SELECT * FROM Win32_MemoryArrayDevice WHERE Name='x'\x00\x00",
        b"\x00" * 128,
        "ROOT\\cimv2 Win32_MemoryArrayDevice Provider".encode("utf-16-le"),
    ])
    od.write_bytes(payload)

    hits = carve_class_context(od, "Win32_MemoryArrayDevice", context_lines=5, window_bytes=4096)
    assert hits, "Expected at least one hit for Win32_MemoryArrayDevice"
    joined = "\n".join("\n".join(h.lines) for h in hits)
    assert "Win32_MemoryArrayDevice" in joined


def test_renderers_include_expected_fields(tmp_path: Path):
    od = tmp_path / "OBJECTS.DATA"
    od.write_bytes(b"Win32_MemoryArrayDevice\x00\x00some text\x00\x00")

    hits = carve_class_context(od, "Win32_MemoryArrayDevice")
    text = render_hits_text(od, "Win32_MemoryArrayDevice", hits)
    js = render_hits_json(od, "Win32_MemoryArrayDevice", hits)

    assert "WMI Class Carver" in text
    assert "Win32_MemoryArrayDevice" in text
    assert '"needle": "Win32_MemoryArrayDevice"' in js


def test_no_hits(tmp_path: Path):
    od = tmp_path / "OBJECTS.DATA"
    od.write_bytes(b"nothing to see here")
    hits = carve_class_context(od, "Win32_MemoryArrayDevice")
    assert hits == []

