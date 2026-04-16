"""Tests for the WMICarver pattern extraction."""

from __future__ import annotations

from pathlib import Path

import pytest

from wmi_forensics.carver import WMICarver, _find_all, _deduplicate, CarverResult
from wmi_forensics.models import (
    CommandLineEventConsumer,
    DataEncoding,
    EventFilter,
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

    def test_prefers_filter_with_query_when_names_collide(self):
        result = CarverResult()
        f1 = EventFilter(
            name="Windows Update",
            query="",
            confidence=0.95,
            encoding=DataEncoding.ASCII,
        )
        f2 = EventFilter(
            name="windows update",
            query="SELECT * FROM __TimerEvent WHERE TimerId='abc'",
            confidence=0.65,
            encoding=DataEncoding.UTF16LE,
        )
        result.filters = [f1, f2]
        _deduplicate(result)
        assert len(result.filters) == 1
        assert result.filters[0].query.startswith("SELECT")

    def test_prefers_consumer_with_command_when_names_collide(self):
        result = CarverResult()
        c1 = CommandLineEventConsumer(
            name="Windows Update",
            consumer_type="CommandLineEventConsumer",
            command_line_template="",
            confidence=0.95,
            encoding=DataEncoding.ASCII,
        )
        c2 = CommandLineEventConsumer(
            name="windows update",
            consumer_type="CommandLineEventConsumer",
            command_line_template="powershell.exe -enc AAAA",
            confidence=0.70,
            encoding=DataEncoding.UTF16LE,
        )
        result.consumers = [c1, c2]
        _deduplicate(result)
        assert len(result.consumers) == 1
        assert "powershell.exe" in result.consumers[0].command_line_template


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

    def test_scoped_consumer_name_equal_class_is_kept(self, tmp_objects_data: Path):
        carver = WMICarver(tmp_objects_data, auto_find_mapping=False)
        ctx = (
            b'CommandLineEventConsumer.Name="CommandLineEventConsumer" '
            b"root\\subscription "
            b'CommandLineTemplate="cmd.exe /c whoami"'
        )
        consumer = carver._parse_consumer(
            ctx, 0x1200, "CommandLineEventConsumer", DataEncoding.ASCII
        )
        assert consumer is not None
        assert consumer.name == "CommandLineEventConsumer"

    def test_generic_name_equal_class_is_rejected_as_schema_noise(self, tmp_objects_data: Path):
        carver = WMICarver(tmp_objects_data, auto_find_mapping=False)
        ctx = (
            b'Name="CommandLineEventConsumer" '
            b"root\\subscription "
            b'CommandLineTemplate="cmd.exe /c whoami"'
        )
        consumer = carver._parse_consumer(
            ctx, 0x1200, "CommandLineEventConsumer", DataEncoding.ASCII
        )
        assert consumer is None

    def test_enriches_missing_query_and_command_with_legacy_patterns(self, tmp_path: Path):
        objects = tmp_path / "OBJECTS.DATA"
        data = b"".join([
            b'_FilterToConsumerBindingCommandLineEventConsumer.Name="Windows Update"'
            b'_EventFilter.Name="Windows Update"'
            b"\x00" * 64,
            b'__EventFilter.Name="Windows Update"' + b"\x00" * 64,
            b'CommandLineEventConsumer.Name="Windows Update"' + b"\x00" * 64,
            b"Windows Update\x00\x00"
            b"SELECT * FROM __InstanceModificationEvent WITHIN 60 "
            b"WHERE TargetInstance ISA 'Win32_Process'"
            b"\x00\x00",
            b"CommandLineEventConsumer\x00\x00"
            b"cmd /C powershell.exe -enc AAABBBCCC=="
            b"\x00Windows Update\x00\x00",
        ])
        objects.write_bytes(data)

        result = WMICarver(objects, auto_find_mapping=False).scan()

        flt = next(f for f in result.filters if f.name == "Windows Update")
        assert "SELECT * FROM __InstanceModificationEvent" in flt.query
        assert all(w.field_name != "query" for w in flt.parse_warnings)

        consumer = next(
            c for c in result.consumers
            if c.consumer_type == "CommandLineEventConsumer" and c.name == "Windows Update"
        )
        assert "powershell.exe -enc" in consumer.command_line_template.lower()
