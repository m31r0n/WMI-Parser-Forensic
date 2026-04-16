"""Tests for the data models."""

from __future__ import annotations

import dataclasses

import pytest

from wmi_forensics.models import (
    CommandLineEventConsumer,
    DataEncoding,
    EventFilter,
    FilterToConsumerBinding,
    ParseWarning,
    RecoveredState,
    RiskDetail,
    WMIPersistenceBundle,
    bundle_to_dict,
)


class TestEventFilter:
    def test_broad_query_no_where(self):
        f = EventFilter(name="test", query="SELECT * FROM __InstanceCreationEvent")
        assert f.is_broad_query() is True

    def test_not_broad_query_with_where(self):
        f = EventFilter(
            name="test",
            query="SELECT * FROM __InstanceCreationEvent WHERE TargetInstance ISA 'Win32_Process'",
        )
        assert f.is_broad_query() is False

    def test_empty_query_not_broad(self):
        f = EventFilter(name="test", query="")
        assert f.is_broad_query() is False

    def test_defaults(self):
        f = EventFilter(name="x")
        assert f.confidence == 1.0
        assert f.recovered_state == RecoveredState.UNKNOWN
        assert f.encoding == DataEncoding.UNKNOWN
        assert f.parse_warnings == []


class TestCommandLineEventConsumer:
    def test_consumer_type_set(self):
        c = CommandLineEventConsumer(name="test", consumer_type="CommandLineEventConsumer")
        # __post_init__ sets consumer_type
        assert c.consumer_type == "CommandLineEventConsumer"

    def test_defaults(self):
        c = CommandLineEventConsumer(name="test", consumer_type="CommandLineEventConsumer")
        assert c.command_line_template == ""
        assert c.executable_path == ""
        assert c.run_interactive_session is None


class TestFilterToConsumerBinding:
    def test_fields(self):
        b = FilterToConsumerBinding(
            consumer_name="TestConsumer",
            consumer_type="CommandLineEventConsumer",
            filter_name="TestFilter",
            namespace=r"root\subscription",
            offset=0x1000,
        )
        assert b.consumer_name == "TestConsumer"
        assert b.offset == 0x1000


class TestWMIPersistenceBundle:
    def test_display_name_from_consumer_and_filter(self):
        bundle = WMIPersistenceBundle(
            consumer=CommandLineEventConsumer(
                name="MyConsumer", consumer_type="CommandLineEventConsumer"
            ),
            event_filter=EventFilter(name="MyFilter"),
        )
        assert bundle.display_name() == "MyConsumer -> MyFilter"

    def test_display_name_falls_back_to_binding(self):
        bundle = WMIPersistenceBundle(
            binding=FilterToConsumerBinding(
                consumer_name="C",
                consumer_type="CommandLineEventConsumer",
                filter_name="F",
            )
        )
        assert bundle.display_name() == "C -> F"

    def test_display_name_unknown(self):
        bundle = WMIPersistenceBundle()
        assert "?" in bundle.display_name()


class TestBundleToDict:
    def test_bytes_become_hex(self):
        b = FilterToConsumerBinding(
            consumer_name="c",
            consumer_type="CommandLineEventConsumer",
            filter_name="f",
            raw_preview=b"\xde\xad\xbe\xef",
        )
        bundle = WMIPersistenceBundle(binding=b)
        d = bundle_to_dict(bundle)
        assert d["binding"]["raw_preview"] == "deadbeef"

    def test_enum_values_are_strings(self):
        bundle = WMIPersistenceBundle(
            binding=FilterToConsumerBinding(
                consumer_name="c",
                consumer_type="CommandLineEventConsumer",
                filter_name="f",
                recovered_state=RecoveredState.ACTIVE,
                encoding=DataEncoding.ASCII,
            )
        )
        d = bundle_to_dict(bundle)
        assert d["binding"]["recovered_state"] == "active"
        assert d["binding"]["encoding"] == "ascii"

    def test_artifact_id_present(self):
        bundle = WMIPersistenceBundle()
        d = bundle_to_dict(bundle)
        assert isinstance(d["artifact_id"], str)
        assert len(d["artifact_id"]) == 36  # UUID format
