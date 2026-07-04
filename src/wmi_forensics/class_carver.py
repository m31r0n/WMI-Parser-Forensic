"""
Class-definition keyword carver for OBJECTS.DATA.

Two views are offered:

* **Structured** (default) — a best-effort CIM class-definition decode via
  :mod:`.cim`: classname, superclass, timestamp, properties (name + CIM type),
  and full untruncated default/string values, laid out like FLARE python-cim.
* **Raw strings** (``--raw``) — grep-style context of printable strings
  (ASCII + UTF-16LE) around each keyword hit, similar to
  ``auto_carve_class_definitions.py ... | grep -C N "<needle>"``.

The structured view falls back to the raw view when no class structure can be
recovered with confidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from .cim import (
    CimClassView,
    PayloadClassHit,
    decode_view_payloads,
    find_payload_classes,
    parse_class_views,
)
from .xlsx_writer import Sheet, workbook_bytes


@dataclass
class ClassCarveHit:
    needle: str
    encoding: str
    offset: int
    context_start: int
    context_end: int
    lines: list[str]


def carve_class_context(
    objects_path: Path,
    needle: str,
    *,
    context_lines: int = 10,
    window_bytes: int = 65_536,
    max_hits: int = 20,
    min_string_len: int = 6,
) -> list[ClassCarveHit]:
    if not needle:
        return []

    data = objects_path.read_bytes()
    hits = _find_keyword_hits(data, needle)
    if not hits:
        return []

    carved: list[ClassCarveHit] = []
    for offset, encoding in hits[:max_hits]:
        start = max(0, offset - window_bytes)
        end = min(len(data), offset + window_bytes)
        chunk = data[start:end]
        strings = _extract_strings(chunk, min_len=min_string_len)
        lines = _grep_context(strings, needle, context_lines)
        carved.append(
            ClassCarveHit(
                needle=needle,
                encoding=encoding,
                offset=offset,
                context_start=start,
                context_end=end,
                lines=lines,
            )
        )
    return carved


def render_hits_text(objects_path: Path, needle: str, hits: list[ClassCarveHit]) -> str:
    out: list[str] = []
    out.append("=" * 72)
    out.append("  WMI Class Carver — Keyword Context Report")
    out.append("=" * 72)
    out.append("")
    out.append(f"  OBJECTS.DATA : {objects_path}")
    out.append(f"  Needle       : {needle}")
    out.append(f"  Hits         : {len(hits)}")

    if not hits:
        out.append("")
        out.append("  No matches found.")
        out.append("")
        out.append("=" * 72)
        return "\n".join(out)

    for i, hit in enumerate(hits, start=1):
        out.append("")
        out.append("-" * 72)
        out.append(
            f"  [{i}] offset=0x{hit.offset:08X}  enc={hit.encoding}  "
            f"window=0x{hit.context_start:08X}-0x{hit.context_end:08X}"
        )
        out.append("-" * 72)
        for line in hit.lines:
            marker = ">>" if needle.lower() in line.lower() else "  "
            out.append(f"{marker} {line}")

    out.append("")
    out.append("=" * 72)
    return "\n".join(out)


def render_hits_xlsx(objects_path: Path, needle: str, hits: list[ClassCarveHit]) -> bytes:
    """One row per extracted context line; full untruncated text in the cell."""
    columns = ["hit", "offset", "encoding", "is_needle", "text"]
    rows = []
    for i, hit in enumerate(hits, start=1):
        for line in hit.lines:
            rows.append([
                i,
                f"0x{hit.offset:08X}",
                hit.encoding,
                needle.lower() in line.lower(),
                line,
            ])
    return workbook_bytes([Sheet("Class Carve", columns, rows)])


def _find_keyword_hits(data: bytes, needle: str) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    ascii_pat = needle.encode("ascii", errors="ignore")
    utf16_pat = needle.encode("utf-16-le", errors="ignore")

    if ascii_pat:
        hits.extend((off, "ascii") for off in _find_all(data, ascii_pat))
    if utf16_pat:
        hits.extend((off, "utf-16-le") for off in _find_all(data, utf16_pat))

    hits.sort(key=lambda h: h[0])
    # Remove exact duplicates (same offset) while preserving order.
    seen_offsets: set[int] = set()
    unique: list[tuple[int, str]] = []
    for off, enc in hits:
        if off in seen_offsets:
            continue
        seen_offsets.add(off)
        unique.append((off, enc))
    return unique


def _find_all(data: bytes, pattern: bytes):
    start = 0
    plen = len(pattern)
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            return
        yield idx
        start = idx + plen


def _extract_strings(chunk: bytes, min_len: int = 6) -> list[str]:
    # ASCII strings
    ascii_re = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    ascii_lines = [m.group(0).decode("ascii", errors="replace") for m in ascii_re.finditer(chunk)]

    # UTF-16LE strings where high byte is null and low byte is printable ASCII.
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")
    utf16_lines = []
    for m in utf16_re.finditer(chunk):
        try:
            utf16_lines.append(m.group(0).decode("utf-16-le", errors="replace"))
        except Exception:
            continue

    return _unique_preserve(ascii_lines + utf16_lines)


def _unique_preserve(lines: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        norm = line.strip()
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    return out


def _grep_context(lines: list[str], needle: str, context_lines: int) -> list[str]:
    if not lines:
        return []

    idxs = [i for i, line in enumerate(lines) if needle.lower() in line.lower()]
    if not idxs:
        # Fallback when the hit is binary-adjacent but not in extracted strings.
        return lines[: min(len(lines), 40)]

    intervals: list[tuple[int, int]] = []
    for i in idxs:
        start = max(0, i - context_lines)
        end = min(len(lines) - 1, i + context_lines)
        intervals.append((start, end))
    merged = _merge_intervals(intervals)

    out: list[str] = []
    for start, end in merged:
        out.extend(lines[start : end + 1])
    return out


# ---------------------------------------------------------------------------
# Structured (CIM class definition) view
# ---------------------------------------------------------------------------

def carve_class_structured(
    objects_path: Path, needle: str, *, max_views: int = 20, decode: bool = False
) -> list[CimClassView]:
    """Best-effort structured decode of the class definition(s) for *needle*.

    When *decode* is True, each default value is also run through the payload
    decoder (Base64 + inflate/gzip → file-type detection)."""
    if not needle:
        return []
    views = parse_class_views(objects_path.read_bytes(), needle, max_views=max_views)
    if decode:
        for v in views:
            decode_view_payloads(v)
    return views


def dump_payloads(views: list[CimClassView], dump_dir: Path) -> list[Path]:
    """Write every decoded payload to *dump_dir*; returns the paths written."""
    written: list[Path] = []
    dump_dir.mkdir(parents=True, exist_ok=True)
    for v in views:
        for value, payload in zip(v.default_values, v.decoded_payloads):
            if payload is None:
                continue
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", v.class_name)[:40] or "class"
            name = f"{safe}_0x{v.offset:08X}_{payload.sha256[:12]}.{payload.extension}"
            path = dump_dir / name
            path.write_bytes(payload.data)
            written.append(path)
    return written


def _payload_note(payload) -> str:
    if payload is None:
        return ""
    chain = " -> ".join(payload.steps)
    return (f"[{payload.file_type} {payload.size} bytes via {chain} "
            f"sha256={payload.sha256}]")


def render_structured_text(objects_path: Path, needle: str, views: list[CimClassView]) -> str:
    out: list[str] = []
    payloads = [(v, p) for v in views for p in v.decoded_payloads if p]

    out.append("=" * 72)
    out.append("  WMI Class Carver — Structured Class Definition (best-effort)")
    out.append("=" * 72)
    out.append("")
    out.append("  [ EXECUTIVE SUMMARY ]")
    out.append(f"    Class name searched : {needle}")
    out.append(f"    Definitions found   : {len(views)}")
    if payloads:
        kinds = ", ".join(sorted({p.file_type for _, p in payloads}))
        out.append(f"    Embedded payloads   : {len(payloads)} ({kinds})")
        out.append("    ** A class property holds an embedded payload — a fileless")
        out.append("       storage technique (MITRE T1546.003). Extract with --dump.")
    else:
        out.append("    Embedded payloads   : none decoded"
                   " (try --decode, or --raw for the string view)")
    out.append("")
    out.append(f"  OBJECTS.DATA : {objects_path}")
    out.append("  NOTE: best-effort decode, not a full CIM parser. Cross-check")
    out.append("        with FLARE python-cim for authoritative results.")

    for i, v in enumerate(views, start=1):
        out.append("")
        out.append("-" * 72)
        out.append(f"  [{i}] classname: {v.class_name}   offset=0x{v.offset:08X}")
        out.append("-" * 72)
        out.append(f"    super     : {v.super_class or '(none)'}")
        out.append(f"    timestamp : {v.timestamp or '(not found)'}")
        out.append(f"    properties: {len(v.properties)}")
        for p in v.properties:
            arr = "[]" if p.is_array else ""
            out.append(
                f"      - {p.name or '(unnamed)'}: {p.cim_type}{arr}"
                f"  index={p.index} level={p.level} offset=0x{p.offset:X}"
            )
        if v.default_values:
            out.append("    default / string values (full):")
            decoded = v.decoded_payloads or [None] * len(v.default_values)
            for val, payload in zip(v.default_values, decoded):
                note = _payload_note(payload)
                if note:
                    out.append(f"      DECODED {note}")
                out.append(f"      * {val}")

    out.append("")
    out.append("=" * 72)
    return "\n".join(out)


def render_structured_xlsx(objects_path: Path, needle: str, views: list[CimClassView]) -> bytes:
    payloads = [(v, p) for v in views for p in v.decoded_payloads if p]

    summary_rows = [
        ["Report", "WMI class definition (structured, best-effort)"],
        ["OBJECTS.DATA", str(objects_path)],
        ["Class searched", needle],
        ["Definitions found", len(views)],
        ["Embedded payloads", len(payloads)],
        ["Payload types", ", ".join(sorted({p.file_type for _, p in payloads})) or "(none)"],
        ["Assessment",
         "Property holds embedded payload (fileless storage, MITRE T1546.003)"
         if payloads else "No embedded payload decoded"],
        ["Note", "Best-effort decode; cross-check with FLARE python-cim"],
    ]
    class_rows = [
        [i, v.class_name, v.super_class, v.timestamp, len(v.properties),
         len(v.default_values), sum(1 for p in v.decoded_payloads if p), f"0x{v.offset:08X}"]
        for i, v in enumerate(views, start=1)
    ]
    prop_rows = [
        [i, v.class_name, p.name, p.cim_type, p.is_array, p.index, p.level, f"0x{p.offset:X}"]
        for i, v in enumerate(views, start=1) for p in v.properties
    ]
    value_rows = []
    for i, v in enumerate(views, start=1):
        decoded = v.decoded_payloads or [None] * len(v.default_values)
        for val, payload in zip(v.default_values, decoded):
            value_rows.append([
                i, v.class_name,
                payload.file_type if payload else "",
                payload.size if payload else "",
                " -> ".join(payload.steps) if payload else "",
                payload.sha256 if payload else "",
                val,
            ])
    sheets = [
        Sheet("Summary", ["Field", "Value"], summary_rows),
        Sheet("Classes", ["#", "classname", "super", "timestamp", "properties", "values", "payloads", "offset"], class_rows),
        Sheet("Properties", ["#", "classname", "name", "cim_type", "is_array", "index", "level", "offset"], prop_rows),
        Sheet("Default Values", ["#", "classname", "payload_type", "payload_size", "decode_chain", "sha256", "value"], value_rows),
    ]
    return workbook_bytes(sheets)


# ---------------------------------------------------------------------------
# Hunt: auto-discover classes whose property values hide payloads
# ---------------------------------------------------------------------------

def hunt_payload_classes(objects_path: Path, *, max_hits: int = 500) -> list[PayloadClassHit]:
    return find_payload_classes(objects_path.read_bytes(), max_hits=max_hits)


def dump_hunt_payloads(hits: list[PayloadClassHit], dump_dir: Path) -> list[Path]:
    written: list[Path] = []
    dump_dir.mkdir(parents=True, exist_ok=True)
    for h in hits:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", h.class_name)[:40] or "class"
        name = f"{safe}_0x{h.value_offset:08X}_{h.payload.sha256[:12]}.{h.payload.extension}"
        path = dump_dir / name
        path.write_bytes(h.payload.data)
        written.append(path)
    return written


def render_hunt_text(objects_path: Path, hits: list[PayloadClassHit]) -> str:
    out: list[str] = []
    out.append("=" * 72)
    out.append("  WMI Payload Hunt — classes storing embedded payloads")
    out.append("=" * 72)
    out.append("")
    out.append("  [ EXECUTIVE SUMMARY ]")
    out.append(f"    OBJECTS.DATA        : {objects_path}")
    out.append(f"    Payload classes     : {len(hits)}")
    if hits:
        kinds = ", ".join(sorted({h.payload.file_type for h in hits}))
        out.append(f"    Payload types       : {kinds}")
        out.append("    ** Executable/script content is stored inside WMI class")
        out.append("       properties (fileless storage, MITRE T1546.003).")
        out.append("       Extract with --dump and analyse in a sandbox / dnSpy.")
    else:
        out.append("    No class-stored payloads found.")

    for i, h in enumerate(hits, start=1):
        out.append("")
        out.append("-" * 72)
        out.append(f"  [{i}] {h.class_name}.{h.property_name or '(property)'}")
        out.append("-" * 72)
        out.append(f"    payload   : {h.payload.file_type}  ({h.payload.size} bytes)")
        out.append(f"    decode    : {' -> '.join(h.payload.steps)}")
        out.append(f"    sha256    : {h.payload.sha256}")
        out.append(f"    timestamp : {h.timestamp or '(not found)'}")
        out.append(f"    offset    : 0x{h.value_offset:08X}")
        if h.payload.preview:
            out.append(f"    preview   : {h.payload.preview}")

    out.append("")
    out.append("=" * 72)
    return "\n".join(out)


def render_hunt_xlsx(objects_path: Path, hits: list[PayloadClassHit]) -> bytes:
    summary_rows = [
        ["Report", "WMI payload hunt (class-as-storage)"],
        ["OBJECTS.DATA", str(objects_path)],
        ["Payload classes found", len(hits)],
        ["Payload types", ", ".join(sorted({h.payload.file_type for h in hits})) or "(none)"],
        ["Technique", "Fileless storage in WMI class property (MITRE T1546.003)"],
        ["Action", "Extract with --dump; analyse in sandbox / dnSpy / ILSpy"],
    ]
    hit_rows = [
        [i, h.class_name, h.property_name, h.payload.file_type, h.payload.size,
         " -> ".join(h.payload.steps), h.payload.sha256, h.timestamp,
         f"0x{h.value_offset:08X}"]
        for i, h in enumerate(hits, start=1)
    ]
    sheets = [
        Sheet("Summary", ["Field", "Value"], summary_rows),
        Sheet("Payloads", ["#", "classname", "property", "type", "size",
                           "decode_chain", "sha256", "timestamp", "offset"], hit_rows),
    ]
    return workbook_bytes(sheets)


def _merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not intervals:
        return []
    intervals = sorted(intervals)
    merged: list[tuple[int, int]] = [intervals[0]]
    for start, end in intervals[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged
