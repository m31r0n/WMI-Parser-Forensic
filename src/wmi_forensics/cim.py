"""
Best-effort structured decoder for WMI CIM class definitions.

The ``carve`` mode uses this to present a class definition the way FLARE
``python-cim`` does — classname, timestamp, properties (name + CIM type), and
full **untruncated** default/string values — instead of a raw string dump.

How it stays accurate on real data
----------------------------------
A class definition stores its strings, property structures and default values
in a **DataRegion**: a ``uint32`` length prefix (top bit set) followed by that
many bytes. Everything is parsed *inside* the bounded DataRegion enclosing the
class-name hit — never a blind fixed-size window — so unrelated bytes elsewhere
in the 20 MB repository cannot masquerade as properties.

Structures used (little-endian):

    DataRegion            uint32 size (size & 0x7FFFFFFF), then `size` bytes
    WMIString             0x00 flag byte + printable text + 0x00
    CimType               type(u8) + array_state(u8) + 2 unknown bytes
    _ClassDefinitionProperty  CimType(4) + index(u16) + offset(u32) + level(u32)
    FILETIME              uint64, 100-ns ticks since 1601

IMPORTANT — this is a *best-effort* decoder, not a byte-perfect CIM parser. It
does not read INDEX.BTR and does not reconstruct the full object graph, so it
may miss or mislabel fields on damaged records and does not resolve the
superclass. For authoritative parsing, cross-check with FLARE ``python-cim``.
When no DataRegion can be bounded, the caller falls back to the raw string view.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .payload import NOTABLE_TYPES, DecodedPayload, decode_payload

CIM_TYPES: dict[int, str] = {
    0x02: "CIM_TYPE_SINT16",
    0x03: "CIM_TYPE_SINT32",
    0x04: "CIM_TYPE_REAL32",
    0x05: "CIM_TYPE_REAL64",
    0x08: "CIM_TYPE_STRING",
    0x0B: "CIM_TYPE_BOOLEAN",
    0x0D: "CIM_TYPE_OBJECT",
    0x10: "CIM_TYPE_SINT8",
    0x11: "CIM_TYPE_UINT8",
    0x12: "CIM_TYPE_UINT16",
    0x13: "CIM_TYPE_UINT32",
    0x14: "CIM_TYPE_SINT64",
    0x15: "CIM_TYPE_UINT64",
    0x65: "CIM_TYPE_DATETIME",
    0x66: "CIM_TYPE_REFERENCE",
    0x67: "CIM_TYPE_CHAR16",
}
_ARRAY_STATES = {0x00, 0x20}

_DR_FLAG = 0x80000000
_DR_MASK = 0x7FFFFFFF
_MIN_DR = 8
_MAX_DR = 16 * 1024 * 1024
_LOOKBACK = 16_384            # how far back to search for the DataRegion prefix
_TS_LOOKBACK = 512           # header bytes before the DataRegion holding the FILETIME

_WMISTRING_RE = re.compile(rb"\x00([\x20-\x7e]{2,})\x00")


@dataclass
class CimProperty:
    name: str
    cim_type: str
    is_array: bool
    index: int
    offset: int
    level: int


@dataclass
class CimClassView:
    class_name: str
    super_class: str = ""
    timestamp: str = ""
    properties: list[CimProperty] = field(default_factory=list)
    default_values: list[str] = field(default_factory=list)  # full, untruncated
    decoded_payloads: list[DecodedPayload | None] = field(default_factory=list)
    offset: int = -1
    data_region_size: int = 0

    @property
    def is_structured(self) -> bool:
        return bool(self.properties or self.default_values)


@dataclass
class PayloadClassHit:
    """A class whose property default value decodes to a real payload."""
    class_name: str
    property_name: str
    timestamp: str
    value_offset: int
    region_start: int
    payload: DecodedPayload


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_class_views(data: bytes, needle: str, *, max_views: int = 20) -> list[CimClassView]:
    """
    Decode a structured view of each class definition whose class name is
    *needle*. Returns [] when nothing bounds/parses, so the caller can fall
    back to the raw string view.
    """
    name_bytes = needle.encode("ascii", errors="ignore")
    if not name_bytes:
        return []

    views: list[CimClassView] = []
    seen: set[int] = set()
    for hit in _find_all(data, name_bytes):
        bounds = _find_data_region(data, hit)
        if bounds is None:
            continue
        region_start, region_end = bounds
        if region_start in seen:
            continue
        seen.add(region_start)

        view = _decode(data, hit, region_start, region_end, needle)
        if view and view.is_structured:
            views.append(view)
        if len(views) >= max_views:
            break
    return views


def decode_view_payloads(view: CimClassView) -> CimClassView:
    """Attempt to decode each default value as an embedded payload, in place."""
    view.decoded_payloads = [decode_payload(v) for v in view.default_values]
    return view


# Large Base64 WMIString — the shape of a payload stored in a class property.
_B64_STRING_RE = re.compile(rb"\x00([A-Za-z0-9+/]{200,}={0,2})\x00")


def find_payload_classes(data: bytes, *, max_hits: int = 500) -> list[PayloadClassHit]:
    """
    Scan the whole repository for class properties whose default value decodes
    to a real payload (PE/.NET/ELF/archive/script) — the "class as storage"
    fileless technique — without needing to know the class name in advance.
    """
    hits: list[PayloadClassHit] = []
    seen: set[tuple[str, str]] = set()
    for m in _B64_STRING_RE.finditer(data):
        value = m.group(1).decode("ascii", errors="replace")
        decoded = decode_payload(value)
        if not decoded or decoded.file_type not in NOTABLE_TYPES:
            continue

        val_off = m.start(1)
        class_name, prop_name, region_start, ts = _locate_class(data, val_off)
        key = (class_name.lower(), decoded.sha256)
        if key in seen:
            continue
        seen.add(key)

        hits.append(PayloadClassHit(
            class_name=class_name, property_name=prop_name, timestamp=ts,
            value_offset=val_off, region_start=region_start, payload=decoded,
        ))
        if len(hits) >= max_hits:
            break
    return hits


def _locate_class(data: bytes, value_offset: int) -> tuple[str, str, int, str]:
    """Best-effort (class_name, property_name, region_start, timestamp) for the
    class definition enclosing the payload value."""
    bounds = _find_data_region(data, value_offset)
    if bounds is not None:
        rstart, rend = bounds
        region = data[rstart:rend]
        strings = _wmi_strings(region)
        class_name = strings[0][1] if strings else "?"
        # Name via property-struct correlation (same as _decode) — more accurate
        # than "nearest string", which would grab a qualifier value like "string".
        name_pool = [(o, t) for o, t in strings if _looks_like_identifier(t) and t != class_name]
        used: set[int] = set()
        prop = ""
        for poff, ptype, _arr, _idx, _off, _lvl in _find_property_structs(region):
            nm = _closest_name(poff, name_pool, used)
            if ptype == "CIM_TYPE_STRING" and nm:
                prop = nm
                break
            prop = prop or nm
        ts = _nearest_filetime(data[max(0, rstart - _TS_LOOKBACK):rstart])
        return class_name, prop, rstart, ts

    back = _wmi_strings(data[max(0, value_offset - 8_192):value_offset])
    class_name = next((t for _, t in reversed(back) if _looks_like_class_name(t)), "?")
    prop = back[-1][1] if back else ""
    return class_name, prop, value_offset, ""


# ---------------------------------------------------------------------------
# DataRegion bounding
# ---------------------------------------------------------------------------

def _find_data_region(data: bytes, hit: int) -> tuple[int, int] | None:
    """
    Find the DataRegion enclosing *hit* by scanning backward for its uint32
    length prefix (top bit set). Returns (data_start, data_end) or None.
    """
    lo = max(0, hit - _LOOKBACK)
    for q in range(hit - 4, lo - 1, -1):
        size = int.from_bytes(data[q:q + 4], "little")
        if not (size & _DR_FLAG):
            continue
        masked = size & _DR_MASK
        if masked < _MIN_DR or masked > _MAX_DR:
            continue
        ds = q + 4
        de = ds + masked
        # A real DataRegion begins with the class-name WMIString, whose first
        # byte is the 0x00 encoding flag. Requiring it rejects spurious high-bit
        # uint32s (e.g. inside a qualifier blob) that happen to enclose the hit.
        if ds <= hit < de <= len(data) and data[ds] == 0x00:
            return ds, de
    return None


# ---------------------------------------------------------------------------
# Decoding (bounded to the DataRegion)
# ---------------------------------------------------------------------------

def _decode(data: bytes, hit: int, region_start: int, region_end: int, needle: str) -> CimClassView | None:
    region = data[region_start:region_end]
    strings = _wmi_strings(region)
    if needle not in {text for _, text in strings}:
        return None

    view = CimClassView(class_name=needle, offset=hit, data_region_size=len(region))
    view.timestamp = _nearest_filetime(data[max(0, region_start - _TS_LOOKBACK):region_start])

    prop_structs = _find_property_structs(region)
    name_pool = [
        (off, text) for off, text in strings
        if text != needle and _looks_like_identifier(text)
    ]
    used: set[int] = set()
    for poff, ptype, is_array, index, offset, level in prop_structs:
        view.properties.append(CimProperty(
            name=_closest_name(poff, name_pool, used),
            cim_type=ptype, is_array=is_array,
            index=index, offset=offset, level=level,
        ))

    view.default_values = _default_values(strings, needle)
    return view


def _wmi_strings(region: bytes) -> list[tuple[int, str]]:
    return [(m.start(1), m.group(1).decode("ascii", errors="replace"))
            for m in _WMISTRING_RE.finditer(region)]


def _find_property_structs(region: bytes):
    out = []
    n = len(region)
    for i in range(n - 14):
        if region[i] not in CIM_TYPES:
            continue
        if region[i + 1] not in _ARRAY_STATES:
            continue
        if region[i + 2] != 0 or region[i + 3] != 0:
            continue
        index, offset, level = struct.unpack_from("<HII", region, i + 4)
        if index > 4096 or level > 256 or offset > _DR_MASK:
            continue
        out.append((i, CIM_TYPES[region[i]], region[i + 1] == 0x20, index, offset, level))
    return _dedupe_structs(out)


def _dedupe_structs(structs):
    out = []
    last_end = -1
    for s in sorted(structs, key=lambda x: x[0]):
        if s[0] < last_end:
            continue
        out.append(s)
        last_end = s[0] + 14
    return out


def _closest_name(struct_off: int, name_pool, used: set[int]) -> str:
    best, best_dist, best_off = "", 1 << 30, -1
    for off, text in name_pool:
        if off in used:
            continue
        dist = abs(off - struct_off)
        if dist < best_dist:
            best_dist, best, best_off = dist, text, off
    if best_off >= 0:
        used.add(best_off)
    return best


def _default_values(strings, needle: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for _, text in strings:
        if text == needle or text in seen:
            continue
        if len(text) >= 24 or _looks_like_payload(text):
            values.append(text)
            seen.add(text)
    return values


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _nearest_filetime(window: bytes) -> str:
    # Scan backward so the FILETIME closest to (just before) the DataRegion —
    # the class definition's own timestamp — wins over neighbouring objects'.
    for i in range(len(window) - 8, -1, -1):
        (qword,) = struct.unpack_from("<Q", window, i)
        if not (128_000_000_000_000_000 < qword < 160_000_000_000_000_000):
            continue
        try:
            dt = datetime(1601, 1, 1) + timedelta(microseconds=qword / 10)
        except (OverflowError, ValueError, OSError):
            continue
        if 2000 <= dt.year <= 2040:
            return dt.isoformat()
    return ""


def _looks_like_identifier(text: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", text))


def _looks_like_class_name(text: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text)) and "_" in text


def _looks_like_payload(text: str) -> bool:
    if re.fullmatch(r"[A-Za-z0-9+/=]{24,}", text):
        return True
    return "\\" in text or "://" in text or "%" in text


def _find_all(data: bytes, pattern: bytes):
    start = 0
    plen = len(pattern)
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            return
        yield idx
        start = idx + plen
