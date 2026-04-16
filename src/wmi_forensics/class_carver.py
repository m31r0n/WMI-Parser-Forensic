"""
Class-definition keyword carver for OBJECTS.DATA.

This module provides a practical workflow similar to:
    auto_carve_class_definitions.py ... | grep -C N "<needle>"

It does not fully parse CIM objects. Instead, it finds keyword hits in raw
binary data (ASCII + UTF-16LE), extracts nearby printable strings, and emits
grep-style context focused on the requested keyword.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import json
import re

_MAX_RENDER_LINE = 240


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
            out.append(f"{marker} {_shorten(line)}")

    out.append("")
    out.append("=" * 72)
    return "\n".join(out)


def render_hits_json(objects_path: Path, needle: str, hits: list[ClassCarveHit]) -> str:
    doc = {
        "objects_data_path": str(objects_path),
        "needle": needle,
        "hit_count": len(hits),
        "hits": [asdict(h) for h in hits],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


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


def _shorten(line: str, max_len: int = _MAX_RENDER_LINE) -> str:
    if len(line) <= max_len:
        return line
    return line[: max_len - 3] + "..."
