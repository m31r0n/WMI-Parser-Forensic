"""
Pattern-based carver for WMI persistence artefacts in OBJECTS.DATA.

WMI stores data in two encoding contexts that the carver exploits:

1. ASCII key paths (B-tree index region)
   Object paths like:
     __FilterToConsumerBinding.Consumer="CommandLineEventConsumer.Name=''evil''"
   appear as single-byte ASCII strings.  Most reliable anchor for bindings.

2. UTF-16LE property values
   WQL queries, command lines, and script text are stored as null-terminated
   UTF-16LE strings inside object data pages.

Every extracted artefact carries the absolute file offset for hex-dump
verification.  Artefacts spanning the overlap boundary between two chunks
may appear twice; the correlator deduplicates by (consumer_name, filter_name).

Known limitations:
- Names with chars outside [\\w\\s\\-_.@] may be truncated.
- UTF-16LE context windows are 3 KB; property data beyond that is not captured.
- Deleted artefacts partially overwritten by reuse may yield incorrect values.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .binary_reader import WMIBinaryReader, find_mapping_file
from .models import (
    ActiveScriptEventConsumer,
    CommandLineEventConsumer,
    DataEncoding,
    EventConsumer,
    EventFilter,
    FilterToConsumerBinding,
    GenericEventConsumer,
    LogFileEventConsumer,
    NTEventLogEventConsumer,
    ParseWarning,
    RecoveredState,
    SMTPEventConsumer,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Search patterns
# ---------------------------------------------------------------------------

_BINDING_ASCII  = b"_FilterToConsumerBinding"
_FILTER_ASCII   = b"__EventFilter"

_CONSUMER_CLASS_NAMES: list[bytes] = [
    b"CommandLineEventConsumer",
    b"ActiveScriptEventConsumer",
    b"NTEventLogEventConsumer",
    b"LogFileEventConsumer",
    b"SMTPEventConsumer",
]

def _u16(s: str) -> bytes:
    return s.encode("utf-16-le")

_BINDING_UTF16 = _u16("__FilterToConsumerBinding")
_FILTER_UTF16  = _u16("__EventFilter")
_CONSUMER_CLASS_NAMES_UTF16 = [_u16(n.decode()) for n in _CONSUMER_CLASS_NAMES]

_CONTEXT_RADIUS = 3_072

# ---------------------------------------------------------------------------
# Regex — applied to decoded UTF-16LE text
# ---------------------------------------------------------------------------

_CONSUMER_REF_RE       = re.compile(r"(\w+EventConsumer)\.Name=[\"]{1,2}([^\"]+)[\"]{1,2}", re.IGNORECASE)
_FILTER_REF_RE         = re.compile(r"_EventFilter\.Name=[\"]{1,2}([^\"]+)[\"]{1,2}", re.IGNORECASE)
_CONSUMER_REF_RE_ASCII = re.compile(rb"(\w+EventConsumer)\.Name=[\"]{1,2}([^\x00\"]+)[\"]{1,2}", re.IGNORECASE)
_FILTER_REF_RE_ASCII   = re.compile(rb"_EventFilter\.Name=[\"]{1,2}([^\x00\"]+)[\"]{1,2}", re.IGNORECASE)

_WQL_RE            = re.compile(r"SELECT\s+\S+\s+FROM\s+\w[\w_]*(?:\s+WHERE\s+.+?)?(?=\x00|\Z)", re.IGNORECASE | re.DOTALL)
_CMDLINE_RE        = re.compile(r"(?:CommandLineTemplate|ExecutablePath)\s*=?\s*[\"' ]?([^\x00\"'\r\n]{4,})", re.IGNORECASE)
_SCRIPT_TEXT_RE    = re.compile(r"ScriptText\s*=?\s*[\"']?([^\x00\"']{10,})", re.IGNORECASE | re.DOTALL)
_SCRIPTING_ENG_RE  = re.compile(r"ScriptingEngine\s*=?\s*[\"']?([^\x00\"'\r\n]{2,32})", re.IGNORECASE)
_SMTP_SERVER_RE    = re.compile(r"SMTPServer\s*=?\s*[\"']?([^\x00\"'\r\n]{2,253})", re.IGNORECASE)
_SMTP_TO_RE        = re.compile(r"ToLine\s*=?\s*[\"']?([^\x00\"'\r\n]{2,})", re.IGNORECASE)
_SMTP_SUBJECT_RE   = re.compile(r"Subject\s*=?\s*[\"']?([^\x00\"'\r\n]{1,})", re.IGNORECASE)
_LOGFILE_NAME_RE   = re.compile(r"Filename\s*=?\s*[\"']?([^\x00\"'\r\n]{2,})", re.IGNORECASE)
_LOGFILE_TEXT_RE   = re.compile(r"\bText\b\s*=?\s*[\"']?([^\x00\"'\r\n]{1,})", re.IGNORECASE)
_EVTLOG_SOURCE_RE  = re.compile(r"SourceName\s*=?\s*[\"']?([^\x00\"'\r\n]{1,})", re.IGNORECASE)
_NAMESPACE_RE      = re.compile(r"(root\\[\w\\]+)", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_all(data: bytes, pattern: bytes) -> Iterator[int]:
    start = 0
    plen = len(pattern)
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        yield idx
        start = idx + plen


def _decode_window(chunk: bytes, anchor: int, radius: int = _CONTEXT_RADIUS) -> tuple[str, int]:
    """Decode a UTF-16LE window around *anchor*. Returns (text, start_offset_in_chunk)."""
    start = max(0, anchor - radius)
    if start % 2:
        start += 1
    end = min(len(chunk), anchor + radius)
    try:
        text = chunk[start:end].decode("utf-16-le", errors="replace")
    except Exception:
        text = ""
    return text, start


def _m(match: re.Match | None, group: int = 1) -> str:
    return match.group(group).strip() if match else ""


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class CarverResult:
    bindings: list[FilterToConsumerBinding] = field(default_factory=list)
    filters:  list[EventFilter]             = field(default_factory=list)
    consumers: list[EventConsumer]          = field(default_factory=list)
    scan_warnings: list[str]               = field(default_factory=list)


# ---------------------------------------------------------------------------
# Carver
# ---------------------------------------------------------------------------

class WMICarver:
    """
    Scans OBJECTS.DATA for WMI persistence artefacts.

        result = WMICarver(Path("OBJECTS.DATA")).scan()
    """

    def __init__(
        self,
        objects_path: Path,
        mapping_path: Path | None = None,
        auto_find_mapping: bool = True,
    ) -> None:
        self.objects_path = objects_path

        if mapping_path is None and auto_find_mapping:
            mapping_path = find_mapping_file(objects_path)
            if mapping_path:
                logger.info("Auto-detected mapping file: %s", mapping_path)

        self._reader = WMIBinaryReader(objects_path, mapping_path)

    def scan(self) -> CarverResult:
        result = CarverResult()
        for chunk_offset, chunk in self._reader.iter_chunks():
            self._scan_bindings(chunk, chunk_offset, result)
            self._scan_filters(chunk, chunk_offset, result)
            self._scan_consumers(chunk, chunk_offset, result)
        _deduplicate(result)
        logger.info(
            "Scan complete: %d bindings, %d filters, %d consumers",
            len(result.bindings), len(result.filters), len(result.consumers),
        )
        return result

    # ------------------------------------------------------------------
    # Bindings
    # ------------------------------------------------------------------

    def _scan_bindings(self, chunk: bytes, chunk_offset: int, result: CarverResult) -> None:
        for local in _find_all(chunk, _BINDING_ASCII):
            b = self._parse_binding_ascii(chunk[local:local + 1024], chunk_offset + local)
            if b:
                result.bindings.append(b)

        for local in _find_all(chunk, _BINDING_UTF16):
            text, _ = _decode_window(chunk, local)
            b = self._parse_binding_utf16(text, chunk_offset + local)
            if b:
                result.bindings.append(b)

    def _parse_binding_ascii(self, ctx: bytes, abs_offset: int) -> FilterToConsumerBinding | None:
        cm = _CONSUMER_REF_RE_ASCII.search(ctx)
        fm = _FILTER_REF_RE_ASCII.search(ctx)
        if not cm or not fm:
            return None

        consumer_type = cm.group(1).decode("ascii", errors="replace")
        consumer_name = cm.group(2).decode("ascii", errors="replace").strip()
        filter_name   = fm.group(1).decode("ascii", errors="replace").strip()
        if not consumer_name or not filter_name:
            return None

        ns_m = re.search(rb"(root\\[\w\\]+)", ctx, re.IGNORECASE)
        namespace = ns_m.group(1).decode("ascii", errors="replace") if ns_m else ""

        return FilterToConsumerBinding(
            consumer_name=consumer_name,
            consumer_type=consumer_type,
            filter_name=filter_name,
            namespace=namespace,
            offset=abs_offset,
            length=len(ctx),
            file_path=str(self.objects_path),
            encoding=DataEncoding.ASCII,
            recovered_state=self._reader.allocation_state_at(abs_offset),
            confidence=0.9,
            raw_preview=ctx[:128],
        )

    def _parse_binding_utf16(self, text: str, abs_offset: int) -> FilterToConsumerBinding | None:
        cm = _CONSUMER_REF_RE.search(text)
        fm = _FILTER_REF_RE.search(text)
        if not cm or not fm:
            return None

        consumer_type = cm.group(1).strip()
        consumer_name = cm.group(2).strip()
        filter_name   = fm.group(1).strip()
        if not consumer_name or not filter_name:
            return None

        ns_m = _NAMESPACE_RE.search(text)
        return FilterToConsumerBinding(
            consumer_name=consumer_name,
            consumer_type=consumer_type,
            filter_name=filter_name,
            namespace=ns_m.group(1) if ns_m else "",
            offset=abs_offset,
            file_path=str(self.objects_path),
            encoding=DataEncoding.UTF16LE,
            recovered_state=self._reader.allocation_state_at(abs_offset),
            confidence=0.8,
        )

    # ------------------------------------------------------------------
    # Filters
    # ------------------------------------------------------------------

    def _scan_filters(self, chunk: bytes, chunk_offset: int, result: CarverResult) -> None:
        for local in _find_all(chunk, _FILTER_ASCII):
            f = self._parse_filter_ascii(chunk[local:local + 2048], chunk_offset + local)
            if f:
                result.filters.append(f)

        for local in _find_all(chunk, _FILTER_UTF16):
            text, _ = _decode_window(chunk, local)
            f = self._parse_filter_utf16(text, chunk_offset + local)
            if f:
                result.filters.append(f)

    def _parse_filter_ascii(self, ctx: bytes, abs_offset: int) -> EventFilter | None:
        m = re.search(rb'__EventFilter\.Name=["\']?([^\x00"\'\\]{1,128})', ctx, re.IGNORECASE)
        if not m:
            return None
        name = m.group(1).decode("ascii", errors="replace").strip()
        if not name:
            return None

        query = self._wql_ascii(ctx)
        ns_m  = re.search(rb"(root\\[\w\\]+)", ctx, re.IGNORECASE)
        warnings: list[ParseWarning] = []
        if not query:
            warnings.append(ParseWarning("query", "WQL not found in ASCII context; may be in UTF-16LE property data", "info"))

        return EventFilter(
            name=name,
            query=query,
            namespace=ns_m.group(1).decode("ascii", errors="replace") if ns_m else "",
            offset=abs_offset,
            file_path=str(self.objects_path),
            encoding=DataEncoding.ASCII,
            recovered_state=self._reader.allocation_state_at(abs_offset),
            confidence=0.85 if query else 0.6,
            raw_preview=ctx[:128],
            parse_warnings=warnings,
        )

    def _parse_filter_utf16(self, text: str, abs_offset: int) -> EventFilter | None:
        m = re.search(r'__EventFilter\.Name=["\']?([^"\'\x00\\]{1,128})', text, re.IGNORECASE)
        if not m:
            m = re.search(r'(?<![A-Za-z])Name\s*=\s*["\']?([^"\'\x00\r\n]{1,128})', text, re.IGNORECASE)
        if not m:
            return None

        name = m.group(1).strip()
        if not name or "\ufffd" in name:
            return None

        qm = _WQL_RE.search(text)
        query = qm.group(0).strip() if qm else ""
        ns_m  = _NAMESPACE_RE.search(text)
        warnings: list[ParseWarning] = []
        if not query:
            warnings.append(ParseWarning("query", "WQL not found in UTF-16LE context", "info"))

        return EventFilter(
            name=name,
            query=query,
            namespace=ns_m.group(1) if ns_m else "",
            offset=abs_offset,
            file_path=str(self.objects_path),
            encoding=DataEncoding.UTF16LE,
            recovered_state=self._reader.allocation_state_at(abs_offset),
            confidence=0.9 if query else 0.65,
            parse_warnings=warnings,
        )

    @staticmethod
    def _wql_ascii(ctx: bytes) -> str:
        m = re.search(rb"SELECT\s+\S+\s+FROM\s+\w[\w_]*[^\x00\r\n]*", ctx, re.IGNORECASE)
        return m.group(0).decode("ascii", errors="replace").strip() if m else ""

    # ------------------------------------------------------------------
    # Consumers
    # ------------------------------------------------------------------

    def _scan_consumers(self, chunk: bytes, chunk_offset: int, result: CarverResult) -> None:
        for ascii_name, utf16_name in zip(_CONSUMER_CLASS_NAMES, _CONSUMER_CLASS_NAMES_UTF16):
            class_str = ascii_name.decode()

            for local in _find_all(chunk, ascii_name):
                c = self._parse_consumer(
                    chunk[local:local + 2048], chunk_offset + local, class_str, DataEncoding.ASCII
                )
                if c:
                    result.consumers.append(c)

            for local in _find_all(chunk, utf16_name):
                text, _ = _decode_window(chunk, local)
                c = self._parse_consumer_utf16(text, chunk_offset + local, class_str)
                if c:
                    result.consumers.append(c)

    def _parse_consumer(
        self, ctx: bytes, abs_offset: int, class_name: str, encoding: DataEncoding
    ) -> EventConsumer | None:
        m = re.search(
            rb"(?:" + class_name.encode() + rb")\.Name=[\"']?([^\x00\"']{1,128})", ctx, re.IGNORECASE
        ) or re.search(rb"Name\s*=\s*[\"']?([^\x00\"']{1,128})", ctx, re.IGNORECASE)
        if not m:
            return None

        name = m.group(1).decode("ascii", errors="replace").strip()
        if not name:
            return None

        ns_m = re.search(rb"(root\\[\w\\]+)", ctx, re.IGNORECASE)
        return self._build_consumer(
            class_name, name,
            ns_m.group(1).decode("ascii", errors="replace") if ns_m else "",
            abs_offset, encoding,
            self._reader.allocation_state_at(abs_offset),
            ctx[:128], "",
        )

    def _parse_consumer_utf16(self, text: str, abs_offset: int, class_name: str) -> EventConsumer | None:
        m = re.search(
            r"(?:" + re.escape(class_name) + r")\.Name=[\"']?([^\"'\x00]{1,128})", text, re.IGNORECASE
        ) or re.search(r"(?<![A-Za-z])Name\s*=\s*[\"']?([^\"'\x00\r\n]{1,128})", text, re.IGNORECASE)
        if not m:
            return None

        name = m.group(1).strip()
        if not name or "\ufffd" in name:
            return None

        ns_m = _NAMESPACE_RE.search(text)
        return self._build_consumer(
            class_name, name,
            ns_m.group(1) if ns_m else "",
            abs_offset, DataEncoding.UTF16LE,
            self._reader.allocation_state_at(abs_offset),
            b"", text,
        )

    def _build_consumer(
        self,
        class_name: str, name: str, namespace: str,
        abs_offset: int, encoding: DataEncoding,
        recovered_state: RecoveredState,
        raw_preview: bytes, text: str,
    ) -> EventConsumer:
        common = dict(
            name=name, consumer_type=class_name, namespace=namespace,
            offset=abs_offset, file_path=str(self.objects_path),
            encoding=encoding, recovered_state=recovered_state,
            confidence=0.85, raw_preview=raw_preview,
        )

        if class_name == "CommandLineEventConsumer":
            return CommandLineEventConsumer(**common, command_line_template=_m(_CMDLINE_RE.search(text)))

        if class_name == "ActiveScriptEventConsumer":
            return ActiveScriptEventConsumer(
                **common,
                script_text=_m(_SCRIPT_TEXT_RE.search(text)),
                scripting_engine=_m(_SCRIPTING_ENG_RE.search(text)),
            )

        if class_name == "NTEventLogEventConsumer":
            return NTEventLogEventConsumer(**common, source_name=_m(_EVTLOG_SOURCE_RE.search(text)))

        if class_name == "LogFileEventConsumer":
            return LogFileEventConsumer(
                **common,
                filename=_m(_LOGFILE_NAME_RE.search(text)),
                text=_m(_LOGFILE_TEXT_RE.search(text)),
            )

        if class_name == "SMTPEventConsumer":
            return SMTPEventConsumer(
                **common,
                smtp_server=_m(_SMTP_SERVER_RE.search(text)),
                to_line=_m(_SMTP_TO_RE.search(text)),
                subject=_m(_SMTP_SUBJECT_RE.search(text)),
            )

        return GenericEventConsumer(**common)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _deduplicate(result: CarverResult) -> None:
    """Remove artefacts found twice due to chunk overlap."""
    seen_b: set[tuple[str, str]] = set()
    result.bindings = [
        b for b in result.bindings
        if (k := (b.consumer_name.lower(), b.filter_name.lower())) not in seen_b
        and not seen_b.add(k)  # type: ignore[func-returns-value]
    ]

    seen_f: set[str] = set()
    result.filters = [
        f for f in result.filters
        if (k := f.name.lower()) not in seen_f and not seen_f.add(k)  # type: ignore[func-returns-value]
    ]

    seen_c: set[tuple[str, str]] = set()
    result.consumers = [
        c for c in result.consumers
        if (k := (c.consumer_type.lower(), c.name.lower())) not in seen_c
        and not seen_c.add(k)  # type: ignore[func-returns-value]
    ]
