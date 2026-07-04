"""Tests for output-path resolution (defaults next to the evidence)."""

from __future__ import annotations

from pathlib import Path

from wmi_forensics.output import (
    default_dump_dir,
    default_report_path,
    resolve_report_path,
)


def test_report_path_is_next_to_evidence(tmp_path):
    od = tmp_path / "Repository" / "OBJECTS.DATA"
    p = default_report_path(od, "persistence", "xlsx")
    assert p.parent == od.parent
    assert p.name.startswith("wmi_persistence_")
    assert p.suffix == ".xlsx"


def test_dump_dir_is_next_to_evidence(tmp_path):
    od = tmp_path / "OBJECTS.DATA"
    d = default_dump_dir(od, "hunt")
    assert d.parent == od.parent
    assert d.name.startswith("wmi_hunt_payloads_")


def test_explicit_output_wins(tmp_path):
    od = tmp_path / "OBJECTS.DATA"
    explicit = tmp_path / "custom.xlsx"
    assert resolve_report_path(str(explicit), od, "rua", "xlsx") == explicit


def test_no_explicit_falls_back_to_evidence(tmp_path):
    od = tmp_path / "OBJECTS.DATA"
    p = resolve_report_path(None, od, "rua", "xlsx")
    assert p.parent == od.parent
