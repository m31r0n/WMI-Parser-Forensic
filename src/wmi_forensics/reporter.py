"""
Output formatters: text (human-readable), JSON (machine-readable), CSV/TSV.

JSON top-level schema:
    scan_metadata : tool, version, timestamp, file paths
    summary       : counts by risk level + orphan counts
    bundles       : list of WMIPersistenceBundle dicts (sorted by risk desc)
    orphaned_filters / orphaned_consumers : artefacts not linked to any binding
"""

from __future__ import annotations

import io
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
from .xlsx_writer import Sheet, workbook_bytes

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
    fmt: str = "txt",
    output_file: Path | None = None,
    objects_path: Path | None = None,
    mapping_path: Path | None = None,
    include_legitimate: bool = False,
    min_risk_score: float = 0.0,
    use_colour: bool = True,
) -> str:
    """
    Render the correlation result.

    ``txt``  : returns the report text (also written to *output_file* if given).
    ``xlsx`` : writes a multi-sheet workbook to *output_file* (required) and
               returns an empty string — a binary workbook cannot go to stdout.
    """
    all_bundles = correlation_result.bundles
    suppressed_legitimate = [b for b in all_bundles if b.is_known_legitimate and not include_legitimate]
    bundles = [
        b for b in all_bundles
        if (include_legitimate or not b.is_known_legitimate)
        and b.risk_score >= min_risk_score
    ]

    if fmt == "xlsx":
        if output_file is None:
            raise ValueError("xlsx format requires an output file (-o FILE)")
        output_file.write_bytes(_xlsx(
            bundles, correlation_result.orphaned_filters,
            correlation_result.orphaned_consumers, objects_path, mapping_path,
        ))
        return ""

    content = _text(bundles, correlation_result.orphaned_filters,
                    correlation_result.orphaned_consumers, use_colour,
                    suppressed_legitimate=suppressed_legitimate)
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
    suppressed_legitimate: list[WMIPersistenceBundle] | None = None,
) -> str:
    suppressed_legitimate = suppressed_legitimate or []
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
    if suppressed_legitimate:
        names = ", ".join(b.display_name() for b in suppressed_legitimate)
        w(f"  Suppressed (legit): {len(suppressed_legitimate)} — {names}")
        w("    (use --include-legitimate to show them)")

    if not bundles:
        w()
        w("  No persistence bindings found above threshold.")

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
        w("  ORPHANED EVENT CONSUMERS  (no binding found)")
        w("  NOTE: may be residual objects from deleted persistence, legitimate")
        w("  providers, or partial carver matches. Verify offsets manually.")
        w("-" * 72)
        for c in orphaned_consumers:
            w()
            w(f"  {c.name}  ({c.consumer_type})")
            w(f"    Namespace: {c.namespace or '(not extracted)'}")
            w(f"    Offset   : 0x{c.offset:08X}  state={c.recovered_state.value}  conf={c.confidence:.0%}" if c.offset >= 0 else "    Offset   : unknown")
            _consumer_details(c, out)

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
# XLSX (multi-sheet workbook)
# ---------------------------------------------------------------------------

_BINDING_COLUMNS = [
    "risk_level", "risk_score", "consumer_name", "consumer_type", "filter_name",
    "namespace", "query", "command_or_script", "binding_offset", "binding_state",
    "binding_confidence", "is_orphaned", "is_incomplete", "is_known_legitimate",
    "detection_summary", "artifact_id",
]


def _command_or_script(b: WMIPersistenceBundle) -> str:
    if isinstance(b.consumer, CommandLineEventConsumer):
        return b.consumer.command_line_template or b.consumer.executable_path
    if isinstance(b.consumer, ActiveScriptEventConsumer):
        return b.consumer.script_text  # full text, not truncated
    return ""


def _xlsx(
    bundles, orphaned_filters, orphaned_consumers, objects_path, mapping_path
) -> bytes:
    ordered = sorted(bundles, key=lambda b: b.risk_score, reverse=True)

    crit = sum(1 for b in bundles if b.risk_level == "critical")
    high = sum(1 for b in bundles if b.risk_level == "high")
    med = sum(1 for b in bundles if b.risk_level == "medium")
    low = sum(1 for b in bundles if b.risk_level == "low")

    top = ordered[0] if ordered else None
    if crit or high:
        verdict = f"ACTION REQUIRED — {crit + high} high/critical persistence binding(s) found"
    elif med:
        verdict = f"REVIEW — {med} medium-risk binding(s) warrant manual investigation"
    elif bundles:
        verdict = "LOW — bindings present but none scored above low risk"
    else:
        verdict = "CLEAN — no WMI event-subscription persistence detected"

    summary_rows = [
        ["Report", "WMI event-subscription persistence"],
        ["Tool", f"wmi-forensics {__version__}"],
        ["Generated (UTC)", datetime.now(timezone.utc).isoformat()],
        ["OBJECTS.DATA", str(objects_path) if objects_path else ""],
        ["MAPPING file", str(mapping_path) if mapping_path else "(none — allocation state UNKNOWN)"],
        ["", ""],
        ["ASSESSMENT", verdict],
        ["Top finding", top.display_name() if top else "(none)"],
        ["Top risk", f"{top.risk_level} {top.risk_score:.2f}" if top else ""],
        ["Recommended action",
         "Confirm each finding in hex at its offset; treat active high/critical "
         "bindings as live persistence and contain the host." if (crit or high)
         else "Review medium findings and the risk factors sheet."],
        ["", ""],
        ["Total bindings", len(bundles)],
        ["Critical", crit],
        ["High", high],
        ["Medium", med],
        ["Low", low],
        ["Orphaned filters", len(orphaned_filters)],
        ["Orphaned consumers", len(orphaned_consumers)],
        ["Note", "Triage scores, not verdicts — always confirm in the raw bytes."],
    ]

    binding_rows = []
    for b in ordered:
        binding_rows.append([
            b.risk_level,
            round(b.risk_score, 3),
            b.consumer.name if b.consumer else (b.binding.consumer_name if b.binding else ""),
            b.consumer.consumer_type if b.consumer else (b.binding.consumer_type if b.binding else ""),
            b.event_filter.name if b.event_filter else (b.binding.filter_name if b.binding else ""),
            (b.binding.namespace if b.binding else "") or (b.event_filter.namespace if b.event_filter else ""),
            b.event_filter.query if b.event_filter else "",
            _command_or_script(b),
            f"0x{b.binding.offset:08X}" if b.binding and b.binding.offset >= 0 else "",
            b.binding.recovered_state.value if b.binding else "",
            f"{b.binding.confidence:.0%}" if b.binding else "",
            b.is_orphaned,
            b.is_incomplete,
            b.is_known_legitimate,
            "; ".join(r.factor for r in b.detection_reasons),
            b.artifact_id,
        ])

    factor_rows = [
        [b.display_name(), b.risk_level, r.factor, round(r.contribution, 3), r.explanation]
        for b in ordered for r in sorted(b.detection_reasons, key=lambda x: x.contribution, reverse=True)
    ]

    filter_rows = [
        [f.name, f.query, f"0x{f.offset:08X}" if f.offset >= 0 else "",
         f.recovered_state.value, f"{f.confidence:.0%}"]
        for f in orphaned_filters
    ]
    consumer_rows = [
        [c.name, c.consumer_type, c.namespace,
         f"0x{c.offset:08X}" if c.offset >= 0 else "", c.recovered_state.value,
         f"{c.confidence:.0%}"]
        for c in orphaned_consumers
    ]

    sheets = [
        Sheet("Summary", ["Field", "Value"], summary_rows),
        Sheet("Bindings", _BINDING_COLUMNS, binding_rows),
        Sheet("Risk Factors", ["binding", "risk_level", "factor", "contribution", "explanation"], factor_rows),
        Sheet("Orphaned Filters", ["name", "query", "offset", "state", "confidence"], filter_rows),
        Sheet("Orphaned Consumers", ["name", "type", "namespace", "offset", "state", "confidence"], consumer_rows),
    ]
    return workbook_bytes(sheets)
