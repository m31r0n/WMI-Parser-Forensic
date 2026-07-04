"""Tests for the reporter module."""

from __future__ import annotations

import io
import zipfile

import pytest

from wmi_forensics.correlator import CorrelationResult
from wmi_forensics.heuristics import score_bundle
from wmi_forensics.models import (
    CommandLineEventConsumer,
    EventFilter,
    FilterToConsumerBinding,
    RecoveredState,
    WMIPersistenceBundle,
)
from wmi_forensics.reporter import write_report


def _simple_bundle(
    consumer_name: str = "TestConsumer",
    filter_name: str = "TestFilter",
    command: str = "cmd.exe /c test",
    risk_score: float | None = None,
) -> WMIPersistenceBundle:
    binding = FilterToConsumerBinding(
        consumer_name=consumer_name,
        consumer_type="CommandLineEventConsumer",
        filter_name=filter_name,
        namespace=r"root\subscription",
        offset=0x1000,
    )
    consumer = CommandLineEventConsumer(
        name=consumer_name,
        consumer_type="CommandLineEventConsumer",
        command_line_template=command,
    )
    flt = EventFilter(name=filter_name, query="SELECT * FROM __TimerEvent")
    bundle = WMIPersistenceBundle(
        binding=binding, consumer=consumer, event_filter=flt
    )
    score_bundle(bundle)
    return bundle


def _make_correlation(bundles, orphaned_filters=None, orphaned_consumers=None):
    cr = CorrelationResult()
    cr.bundles = bundles
    cr.orphaned_filters = orphaned_filters or []
    cr.orphaned_consumers = orphaned_consumers or []
    return cr


class TestTextReporter:
    def test_produces_output(self):
        cr = _make_correlation([_simple_bundle()])
        report = write_report(cr, fmt="text", use_colour=False)
        assert "WMI Persistence Finder" in report
        assert "TestConsumer" in report
        assert "TestFilter" in report

    def test_shows_risk_level(self):
        cr = _make_correlation([_simple_bundle()])
        report = write_report(cr, fmt="text", use_colour=False)
        # Should contain one of the risk labels
        assert any(level in report.upper() for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"))

    def test_shows_offset_in_hex(self):
        cr = _make_correlation([_simple_bundle()])
        report = write_report(cr, fmt="text", use_colour=False)
        assert "0x00001000" in report

    def test_empty_result_no_crash(self):
        cr = _make_correlation([])
        report = write_report(cr, fmt="text", use_colour=False)
        assert "END OF REPORT" in report

    def test_legitimate_hidden_by_default(self):
        bundle = _simple_bundle(consumer_name="BVTConsumer", filter_name="BVTFilter")
        score_bundle(bundle)
        cr = _make_correlation([bundle])
        report = write_report(cr, fmt="text", use_colour=False, include_legitimate=False)
        # The name appears in the "Suppressed (legit)" summary line but NOT as a full binding
        assert "[ BINDING ]" not in report
        assert "Suppressed" in report

    def test_legitimate_shown_when_requested(self):
        bundle = _simple_bundle(consumer_name="BVTConsumer", filter_name="BVTFilter")
        score_bundle(bundle)
        cr = _make_correlation([bundle])
        report = write_report(cr, fmt="text", use_colour=False, include_legitimate=True)
        assert "BVTConsumer" in report

    def test_min_risk_filter(self):
        low_bundle = _simple_bundle(consumer_name="LowRisk", filter_name="LowFilter")
        low_bundle.risk_score = 0.1
        low_bundle.risk_level = "low"
        high_bundle = _simple_bundle(consumer_name="HighRisk", filter_name="HighFilter")
        high_bundle.risk_score = 0.7
        high_bundle.risk_level = "high"
        cr = _make_correlation([low_bundle, high_bundle])
        report = write_report(cr, fmt="text", use_colour=False, min_risk_score=0.6)
        assert "HighRisk" in report
        assert "LowRisk" not in report


def _sheet_text(data: bytes, sheet_no: int = 2) -> str:
    zf = zipfile.ZipFile(io.BytesIO(data))
    return zf.read(f"xl/worksheets/sheet{sheet_no}.xml").decode("utf-8")


class TestXlsxReporter:
    def test_requires_output_file(self):
        cr = _make_correlation([_simple_bundle()])
        with pytest.raises(ValueError):
            write_report(cr, fmt="xlsx", output_file=None)

    def test_writes_workbook(self, tmp_path):
        cr = _make_correlation([_simple_bundle()])
        out = tmp_path / "report.xlsx"
        result = write_report(cr, fmt="xlsx", output_file=out)
        assert result == ""
        assert out.exists()
        zf = zipfile.ZipFile(out)
        # Summary + Bindings + Risk Factors + Orphaned Filters/Consumers
        assert "xl/worksheets/sheet5.xml" in zf.namelist()

    def test_bindings_sheet_has_data(self, tmp_path):
        cr = _make_correlation([_simple_bundle()])
        out = tmp_path / "report.xlsx"
        write_report(cr, fmt="xlsx", output_file=out)
        bindings = _sheet_text(out.read_bytes(), sheet_no=2)
        assert "TestConsumer" in bindings
        assert "TestFilter" in bindings

    def test_full_command_not_truncated(self, tmp_path):
        long_cmd = "powershell -enc " + "A" * 2000
        cr = _make_correlation([_simple_bundle(command=long_cmd)])
        out = tmp_path / "report.xlsx"
        write_report(cr, fmt="xlsx", output_file=out)
        assert long_cmd in _sheet_text(out.read_bytes(), sheet_no=2)
