"""Tests for the WMICarver pattern extraction."""

from __future__ import annotations

from pathlib import Path

import pytest

from wmi_forensics.carver import WMICarver, _find_all, _deduplicate, CarverResult
from wmi_forensics.models import (
    CommandLineEventConsumer,
    FilterToConsumerBinding,
    RecoveredState,
)


class TestFindAll:
    def test_single_match(self):
        data = b"hello world hello"
        assert list(_find_all(data, b"world")) == [6]

    def test_multiple_matches(self):
        data = b"abcabc"
        assert list(_find_all(data, b"abc")) == [0, 3]

    def test_no_match(self):
        data = b"hello"
        assert list(_find_all(data, b"xyz")) == []

    def test_empty_data(self):
        assert list(_find_all(b"", b"abc")) == []


class TestDeduplicate:
    def test_removes_duplicate_bindings(self):
        result = CarverResult()
        b1 = FilterToConsumerBinding(
            consumer_name="Foo", consumer_type="CommandLineEventConsumer",
            filter_name="Bar", offset=100
        )
        b2 = FilterToConsumerBinding(
            consumer_name="foo", consumer_type="CommandLineEventConsumer",
            filter_name="bar", offset=200  # same name, different case/offset
        )
        result.bindings = [b1, b2]
        _deduplicate(result)
        assert len(result.bindings) == 1

    def test_keeps_different_bindings(self):
        result = CarverResult()
        b1 = FilterToConsumerBinding(
            consumer_name="A", consumer_type="CommandLineEventConsumer",
            filter_name="X", offset=0
        )
        b2 = FilterToConsumerBinding(
            consumer_name="B", consumer_type="CommandLineEventConsumer",
            filter_name="Y", offset=100
        )
        result.bindings = [b1, b2]
        _deduplicate(result)
        assert len(result.bindings) == 2


class TestWMICarverScan:
    def test_finds_binding_ascii(self, tmp_objects_data: Path):
        carver = WMICarver(tmp_objects_data, auto_find_mapping=False)
        result = carver.scan()
        consumer_names = {b.consumer_name.lower() for b in result.bindings}
        # The synthetic file has these consumer names
        assert "backdoor_consumer" in consumer_names or "bvtconsumer" in consumer_names

    def test_finds_activescript_binding(self, tmp_objects_data: Path):
        carver = WMICarver(tmp_objects_data, auto_find_mapping=False)
        result = carver.scan()
        types = {b.consumer_type for b in result.bindings}
        assert any("Script" in t for t in types) or any("CommandLine" in t for t in types)

    def test_empty_file_produces_no_results(self, tmp_objects_data_empty: Path):
        carver = WMICarver(tmp_objects_data_empty, auto_find_mapping=False)
        result = carver.scan()
        assert result.bindings == []

    def test_binding_has_offset(self, tmp_objects_data: Path):
        carver = WMICarver(tmp_objects_data, auto_find_mapping=False)
        result = carver.scan()
        for binding in result.bindings:
            assert binding.offset >= 0, "Every binding must have a valid file offset"

    def test_binding_has_file_path(self, tmp_objects_data: Path):
        carver = WMICarver(tmp_objects_data, auto_find_mapping=False)
        result = carver.scan()
        for binding in result.bindings:
            assert binding.file_path != ""

    def test_scan_with_mapping_file(self, tmp_objects_data: Path, tmp_mapping_file: Path):
        carver = WMICarver(tmp_objects_data, mapping_path=tmp_mapping_file)
        result = carver.scan()
        # Should run without error even with a mapping file present
        assert isinstance(result, CarverResult)

    def test_bvt_binding_found(self, tmp_objects_data: Path):
        carver = WMICarver(tmp_objects_data, auto_find_mapping=False)
        result = carver.scan()
        consumer_names = {b.consumer_name.lower() for b in result.bindings}
        assert "bvtconsumer" in consumer_names
