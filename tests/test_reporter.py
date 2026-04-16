"""Tests for the reporter module."""

from __future__ import annotations

import json

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


class TestJsonReporter:
    def test_valid_json(self):
        cr = _make_correlation([_simple_bundle()])
        report = write_report(cr, fmt="json", use_colour=False)
        doc = json.loads(report)
        assert "bundles" in doc
        assert "summary" in doc
        assert "scan_metadata" in doc

    def test_bundle_fields_present(self):
        cr = _make_correlation([_simple_bundle()])
        doc = json.loads(write_report(cr, fmt="json"))
        b = doc["bundles"][0]
        assert "artifact_id" in b
        assert "risk_score" in b
        assert "risk_level" in b
        assert "detection_reasons" in b
        assert "binding" in b

    def test_bytes_are_hex_strings(self):
        """raw_preview bytes must be serialised as hex strings, not crash."""
        bundle = _simple_bundle()
        bundle.binding.raw_preview = b"\xde\xad\xbe\xef"
        cr = _make_correlation([bundle])
        doc = json.loads(write_report(cr, fmt="json"))
        assert doc["bundles"][0]["binding"]["raw_preview"] == "deadbeef"

    def test_empty_result_valid_json(self):
        cr = _make_correlation([])
        doc = json.loads(write_report(cr, fmt="json"))
        assert doc["bundles"] == []
        assert doc["summary"]["total_bundles"] == 0

    def test_summary_counts(self):
        bundles = []
        for i in range(3):
            b = _simple_bundle(consumer_name=f"C{i}", filter_name=f"F{i}")
            b.risk_score = 0.7
            b.risk_level = "high"
            bundles.append(b)
        cr = _make_correlation(bundles)
        doc = json.loads(write_report(cr, fmt="json"))
        assert doc["summary"]["total_bundles"] == 3
        assert doc["summary"]["high"] == 3


class TestCsvReporter:
    def test_produces_tsv_header(self):
        cr = _make_correlation([_simple_bundle()])
        report = write_report(cr, fmt="csv", use_colour=False)
        assert "artifact_id" in report
        assert "risk_level" in report
        assert "consumer_name" in report

    def test_one_row_per_bundle(self):
        bundles = [_simple_bundle(consumer_name=f"C{i}", filter_name=f"F{i}") for i in range(3)]
        cr = _make_correlation(bundles)
        report = write_report(cr, fmt="csv")
        lines = [l for l in report.strip().split("\n") if l]
        # header + 3 data rows
        assert len(lines) == 4
