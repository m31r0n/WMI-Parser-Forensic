"""
Output formatters: text (human-readable), JSON (machine-readable), CSV/TSV.

JSON top-level schema:
    scan_metadata : tool, version, timestamp, file paths
    summary       : counts by risk level + orphan counts
    bundles       : list of WMIPersistenceBundle dicts (sorted by risk desc)
    orphaned_filters / orphaned_consumers : artefacts not linked to any binding
"""

from __future__ import annotations

import csv
import dataclasses
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .correlator import CorrelationResult
from .models import (
    ActiveScriptEventConsumer,
    CommandLineEventConsumer,
    EventConsumer,
    EventFilter,
    LogFileEventConsumer,
    NTEventLogEventConsumer,
    SMTPEventConsumer,
    WMIPersistenceBundle,
)

_RISK_COLOUR = {
    "low":      "\033[32m",
    "medium":   "\033[33m",
    "high":     "\033[91m",
    "critical": "\033[31;1m",
    "unknown":  "\033[37m",
}
_RESET = "\033[0m"


def write_report(
    correlation_result: CorrelationResult,
    fmt: str = "text",
    output_file: Path | None = None,
    objects_path: Path | None = None,
    mapping_path: Path | None = None,
    include_legitimate: bool = False,
    min_risk_score: float = 0.0,
    use_colour: bool = True,
) -> str:
    bundles = [
        b for b in correlation_result.bundles
        if (include_legitimate or not b.is_known_legitimate)
        and b.risk_score >= min_risk_score
    ]

    if fmt == "json":
        content = _json(bundles, correlation_result.orphaned_filters,
                        correlation_result.orphaned_consumers, objects_path, mapping_path)
    elif fmt in ("csv", "tsv"):
        content = _csv(bundles)
    else:
        content = _text(bundles, correlation_result.orphaned_filters,
                        correlation_result.orphaned_consumers, use_colour)

    if output_file:
        output_file.write_text(content, encoding="utf-8")
    return content


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------

def _text(
    bundles: list[WMIPersistenceBundle],
    orphaned_filters: list[EventFilter],
    orphaned_consumers: list[EventConsumer],
    use_colour: bool,
) -> str:
    out = io.StringIO()
    w = lambda s="": out.write(s + "\n")

    w("=" * 72)
    w("  WMI Persistence Finder — Forensic Report")
    w(f"  Generated: {datetime.now(timezone.utc).isoformat()}")
    w("=" * 72)
    w()
    w(f"  Bindings found    : {len(bundles)}")
    w(f"  Critical/High     : {sum(1 for b in bundles if b.risk_level in ('high','critical'))}")
    w(f"  Medium            : {sum(1 for b in bundles if b.risk_level == 'medium')}")
    w(f"  Low               : {sum(1 for b in bundles if b.risk_level == 'low')}")
    w(f"  Orphaned filters  : {len(orphaned_filters)}")
    w(f"  Orphaned consumers: {len(orphaned_consumers)}")

    if not bundles:
        w()
        w("  No persistence bindings found (above threshold).")

    for bundle in sorted(bundles, key=lambda b: b.risk_score, reverse=True):
        _bundle_text(bundle, out, use_colour)

    if orphaned_filters:
        w()
        w("-" * 72)
        w("  ORPHANED EVENT FILTERS")
        w("-" * 72)
        for f in orphaned_filters:
            w(f"  {f.name}")
            w(f"    Query  : {f.query or '(not extracted)'}")
            w(f"    Offset : 0x{f.offset:08X}" if f.offset >= 0 else "    Offset : unknown")
            w(f"    State  : {f.recovered_state.value}  conf={f.confidence:.0%}")

    if orphaned_consumers:
        w()
        w("-" * 72)
        w("  ORPHANED EVENT CONSUMERS")
        w("-" * 72)
        for c in orphaned_consumers:
            w(f"  {c.name}  ({c.consumer_type})")
            w(f"    Offset : 0x{c.offset:08X}" if c.offset >= 0 else "    Offset : unknown")
            w(f"    State  : {c.recovered_state.value}  conf={c.confidence:.0%}")

    w()
    w("=" * 72)
    w("  END OF REPORT")
    w("=" * 72)
    return out.getvalue()


def _colour(text: str, level: str, use_colour: bool) -> str:
    return f"{_RISK_COLOUR.get(level,'')}{text}{_RESET}" if use_colour else text


def _bundle_text(b: WMIPersistenceBundle, out: io.StringIO, use_colour: bool) -> None:
    w = lambda s="": out.write(s + "\n")
    tag = f"[{b.risk_level.upper()}  {b.risk_score:.2f}]"
    w()
    w("-" * 72)
    w(f"  {_colour(tag, b.risk_level, use_colour)}  {b.display_name()}")
    w("-" * 72)
    w(f"  Artifact ID    : {b.artifact_id}")
    if b.is_known_legitimate:
        w(f"  Legitimate     : Yes — {b.legitimacy_note}")
    w(f"  Orphaned       : {b.is_orphaned}   Incomplete: {b.is_incomplete}")

    if b.binding:
        bd = b.binding
        w()
        w("  [ BINDING ]")
        w(f"    Consumer : {bd.consumer_name}  ({bd.consumer_type})")
        w(f"    Filter   : {bd.filter_name}")
        w(f"    Namespace: {bd.namespace or '(not extracted)'}")
        w(f"    Offset   : 0x{bd.offset:08X}  enc={bd.encoding.value}  state={bd.recovered_state.value}  conf={bd.confidence:.0%}")

    if b.event_filter:
        f = b.event_filter
        w()
        w("  [ EVENT FILTER ]")
        w(f"    Name     : {f.name}")
        w(f"    Query    : {f.query or '(not extracted)'}")
        w(f"    Offset   : 0x{f.offset:08X}  state={f.recovered_state.value}  conf={f.confidence:.0%}" if f.offset >= 0 else "    Offset   : unknown")
        for pw in f.parse_warnings:
            w(f"    Warning  : [{pw.severity.upper()}] {pw.field_name}: {pw.message}")
    else:
        w()
        w("  [ EVENT FILTER ]  — not resolved")

    if b.consumer:
        c = b.consumer
        w()
        w("  [ CONSUMER ]")
        w(f"    Name     : {c.name}  ({c.consumer_type})")
        w(f"    Offset   : 0x{c.offset:08X}  state={c.recovered_state.value}  conf={c.confidence:.0%}" if c.offset >= 0 else "    Offset   : unknown")
        _consumer_details(c, out)
    else:
        w()
        w("  [ CONSUMER ]  — not resolved")

    if b.detection_reasons:
        w()
        w("  [ RISK FACTORS ]")
        for r in sorted(b.detection_reasons, key=lambda x: x.contribution, reverse=True):
            w(f"    +{r.contribution:.2f}  {r.factor}")
            w(f"           {r.explanation}")


def _consumer_details(c: EventConsumer, out: io.StringIO) -> None:
    w = lambda s="": out.write(s + "\n")
    if isinstance(c, CommandLineEventConsumer):
        if c.command_line_template:
            w(f"    Command  : {c.command_line_template}")
        if c.executable_path:
            w(f"    Executable: {c.executable_path}")
    elif isinstance(c, ActiveScriptEventConsumer):
        w(f"    Engine   : {c.scripting_engine or '(unknown)'}")
        if c.script_filename:
            w(f"    File     : {c.script_filename}")
        if c.script_text:
            preview = c.script_text[:200].replace("\n", "\\n")
            w(f"    Script   : {preview}{'...' if len(c.script_text) > 200 else ''}")
    elif isinstance(c, NTEventLogEventConsumer):
        w(f"    Source   : {c.source_name or '(not extracted)'}")
        if c.event_id is not None:
            w(f"    Event ID : {c.event_id}")
    elif isinstance(c, LogFileEventConsumer):
        w(f"    Log file : {c.filename or '(not extracted)'}")
        if c.text:
            w(f"    Text     : {c.text[:120]}")
    elif isinstance(c, SMTPEventConsumer):
        w(f"    Server   : {c.smtp_server or '(not extracted)'}")
        w(f"    To       : {c.to_line or '(not extracted)'}")
        if c.subject:
            w(f"    Subject  : {c.subject}")


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def _serialise(obj):
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _serialise(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, bytes):
        return obj.hex()
    if hasattr(obj, "value"):
        return obj.value
    if isinstance(obj, list):
        return [_serialise(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _serialise(v) for k, v in obj.items()}
    return obj


def _json(
    bundles, orphaned_filters, orphaned_consumers, objects_path, mapping_path
) -> str:
    doc = {
        "scan_metadata": {
            "tool": "wmi-forensics",
            "version": __version__,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "objects_data_path": str(objects_path) if objects_path else None,
            "mapping_file_path": str(mapping_path) if mapping_path else None,
        },
        "summary": {
            "total_bundles":      len(bundles),
            "critical":           sum(1 for b in bundles if b.risk_level == "critical"),
            "high":               sum(1 for b in bundles if b.risk_level == "high"),
            "medium":             sum(1 for b in bundles if b.risk_level == "medium"),
            "low":                sum(1 for b in bundles if b.risk_level == "low"),
            "orphaned_filters":   len(orphaned_filters),
            "orphaned_consumers": len(orphaned_consumers),
        },
        "bundles":            [_serialise(b) for b in sorted(bundles, key=lambda b: b.risk_score, reverse=True)],
        "orphaned_filters":   [_serialise(f) for f in orphaned_filters],
        "orphaned_consumers": [_serialise(c) for c in orphaned_consumers],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

_CSV_FIELDS = [
    "artifact_id", "risk_level", "risk_score",
    "consumer_name", "consumer_type", "filter_name", "namespace",
    "query", "command_or_script",
    "binding_offset", "binding_state", "binding_confidence",
    "is_orphaned", "is_incomplete", "is_known_legitimate",
    "detection_summary",
]


def _csv(bundles: list[WMIPersistenceBundle]) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=_CSV_FIELDS, delimiter="\t",
                            extrasaction="ignore", lineterminator="\n")
    writer.writeheader()

    for b in sorted(bundles, key=lambda b: b.risk_score, reverse=True):
        cmd_or_script = ""
        if isinstance(b.consumer, CommandLineEventConsumer):
            cmd_or_script = b.consumer.command_line_template
        elif isinstance(b.consumer, ActiveScriptEventConsumer):
            cmd_or_script = b.consumer.script_text[:500]

        writer.writerow({
            "artifact_id":       b.artifact_id,
            "risk_level":        b.risk_level,
            "risk_score":        f"{b.risk_score:.3f}",
            "consumer_name":     b.consumer.name if b.consumer else (b.binding.consumer_name if b.binding else ""),
            "consumer_type":     b.consumer.consumer_type if b.consumer else (b.binding.consumer_type if b.binding else ""),
            "filter_name":       b.event_filter.name if b.event_filter else (b.binding.filter_name if b.binding else ""),
            "namespace":         (b.binding.namespace if b.binding else "") or (b.event_filter.namespace if b.event_filter else ""),
            "query":             b.event_filter.query if b.event_filter else "",
            "command_or_script": cmd_or_script,
            "binding_offset":    f"0x{b.binding.offset:08X}" if b.binding and b.binding.offset >= 0 else "",
            "binding_state":     b.binding.recovered_state.value if b.binding else "",
            "binding_confidence": f"{b.binding.confidence:.0%}" if b.binding else "",
            "is_orphaned":       b.is_orphaned,
            "is_incomplete":     b.is_incomplete,
            "is_known_legitimate": b.is_known_legitimate,
            "detection_summary": "; ".join(r.factor for r in b.detection_reasons),
        })

    return out.getvalue()
