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

# Normalised set used to reject class-definition noise.
# When the extracted Name equals a known class name, the carver has matched
# the schema definition, not an object instance — discard it.
_CONSUMER_CLASS_NAME_SET: frozenset[str] = frozenset(
    n.decode().lower() for n in _CONSUMER_CLASS_NAMES
)

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

_WQL_RE            = re.compile(r"SELECT\s+\S+\s+FROM\s+\w[\w_]*[^\x00\r\n]*", re.IGNORECASE)
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

# Legacy-oriented fallback patterns used only when modern property extraction
# misses query/command fields.
_WQL_BYTES_RE = re.compile(
    rb"SELECT\s+\S+\s+FROM\s+\w[\w_]*[^\x00\r\n]*",
    re.IGNORECASE,
)
_CMD_FALLBACK_RE = re.compile(
    r"(?:cmd(?:\.exe)?\s*/[ck]\s+)?"
    r"(?:powershell(?:\.exe)?|pwsh|wscript|cscript|mshta|regsvr32|rundll32|"
    r"certutil|bitsadmin|msiexec|wmic|schtasks|at\.exe|installutil|regasm|"
    r"regsvcs|odbcconf|ieexec|curl|wget)\b[^\x00\r\n]{0,20000}",
    re.IGNORECASE,
)

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
        self._enrich_missing_fields(result)
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
        scoped = re.search(
            rb"(?:" + class_name.encode() + rb")\.Name=[\"']?([^\x00\"']{1,128})", ctx, re.IGNORECASE
        )
        generic = None if scoped else re.search(
            rb"Name\s*=\s*[\"']?([^\x00\"']{1,128})", ctx, re.IGNORECASE
        )
        m = scoped or generic
        if not m:
            return None

        name = m.group(1).decode("ascii", errors="replace").strip()
        if not name:
            return None
        if generic is not None and name.lower() in _CONSUMER_CLASS_NAME_SET:
            # Reject schema noise only for generic Name= fallback matches.
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
        scoped = re.search(
            r"(?:" + re.escape(class_name) + r")\.Name=[\"']?([^\"'\x00]{1,128})", text, re.IGNORECASE
        )
        generic = None if scoped else re.search(
            r"(?<![A-Za-z])Name\s*=\s*[\"']?([^\"'\x00\r\n]{1,128})", text, re.IGNORECASE
        )
        m = scoped or generic
        if not m:
            return None

        name = m.group(1).strip()
        if not name or "\ufffd" in name:
            return None
        if generic is not None and name.lower() in _CONSUMER_CLASS_NAME_SET:
            # Reject schema noise only for generic Name= fallback matches.
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

    # ------------------------------------------------------------------
    # Enrichment (legacy fallback patterns)
    # ------------------------------------------------------------------

    def _enrich_missing_fields(self, result: CarverResult) -> None:
        """
        Recover fields often stored far from class-name anchors:
        - EventFilter.query
        - CommandLineEventConsumer.command_line_template

        This uses legacy regex fallback inspired by the original
        PyWMIPersistenceFinder heuristics.
        """
        filters_missing_query = [f for f in result.filters if f.name and not f.query]
        consumers_missing_cmd = [
            c for c in result.consumers
            if isinstance(c, CommandLineEventConsumer)
            and c.name
            and not (c.command_line_template or c.executable_path)
        ]
        if not filters_missing_query and not consumers_missing_cmd:
            return

        try:
            data = self.objects_path.read_bytes()
        except OSError as exc:
            logger.debug("Enrichment skipped (cannot read %s): %s", self.objects_path, exc)
            return

        for event_filter in filters_missing_query:
            query = self._recover_filter_query(event_filter.name, data)
            if not query:
                continue
            event_filter.query = query
            event_filter.confidence = max(event_filter.confidence, 0.85)
            event_filter.parse_warnings = [
                w for w in event_filter.parse_warnings if w.field_name != "query"
            ]

        for consumer in consumers_missing_cmd:
            command = self._recover_command_line(consumer.name, data)
            if not command:
                continue
            consumer.command_line_template = command
            consumer.confidence = max(consumer.confidence, 0.9)

    def _recover_filter_query(self, filter_name: str, data: bytes) -> str:
        name_bytes = filter_name.encode("ascii", errors="ignore")
        if not name_bytes:
            return ""

        # Legacy pattern: <name>\x00\x00<query>\x00\x00
        best = ""
        pattern = re.compile(re.escape(name_bytes) + rb"\x00\x00([^\x00]{8,4096})\x00\x00", re.IGNORECASE)
        for match in pattern.finditer(data):
            segment = match.group(1)
            if wql := _WQL_BYTES_RE.search(segment):
                candidate = wql.group(0).decode("ascii", errors="replace").strip()
                if len(candidate) > len(best):
                    best = candidate

        if best:
            return best

        # Fallback: query may be nearby in another structure window.
        return self._recover_query_near_name(filter_name, data)

    def _recover_query_near_name(self, name: str, data: bytes) -> str:
        best = ""

        def scan_text(text: str) -> None:
            nonlocal best
            for match in _WQL_RE.finditer(text):
                candidate = match.group(0).strip()
                if len(candidate) > len(best):
                    best = candidate

        name_ascii = name.encode("ascii", errors="ignore")
        if name_ascii:
            for hit in _find_all(data, name_ascii):
                start = max(0, hit - 8_192)
                end = min(len(data), hit + 65_536)
                scan_text(data[start:end].decode("ascii", errors="replace"))

        name_utf16 = name.encode("utf-16-le", errors="ignore")
        if name_utf16:
            for hit in _find_all(data, name_utf16):
                start = max(0, hit - 16_384)
                if start % 2:
                    start += 1
                end = min(len(data), hit + 131_072)
                scan_text(data[start:end].decode("utf-16-le", errors="replace"))

        return best

    def _recover_command_line(self, consumer_name: str, data: bytes) -> str:
        name_bytes = consumer_name.encode("ascii", errors="ignore")
        if not name_bytes:
            return ""

        best = ""
        pattern = re.compile(
            rb"CommandLineEventConsumer\x00\x00(.*?)\x00"
            + re.escape(name_bytes)
            + rb"(?:\x00\x00)?([^\x00]*)?",
            re.IGNORECASE | re.DOTALL,
        )
        for match in pattern.finditer(data):
            for group_idx in (1, 2):
                blob = match.group(group_idx) or b""
                candidate = self._extract_command_candidate(blob.decode("ascii", errors="replace"))
                if len(candidate) > len(best):
                    best = candidate

        if best:
            return best

        # Fallback around explicit consumer-name hits.
        for hit in _find_all(data, name_bytes):
            start = max(0, hit - 16_384)
            end = min(len(data), hit + 131_072)
            candidate = self._extract_command_candidate(
                data[start:end].decode("ascii", errors="replace")
            )
            if len(candidate) > len(best):
                best = candidate

        return best

    @staticmethod
    def _extract_command_candidate(text: str) -> str:
        if m := _CMDLINE_RE.search(text):
            return m.group(1).strip()
        if m := _CMD_FALLBACK_RE.search(text):
            return m.group(0).strip()
        return ""


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _deduplicate(result: CarverResult) -> None:
    """Remove artefacts found twice due to chunk overlap."""
    result.bindings = _dedupe_best(
        result.bindings,
        key_fn=lambda b: (b.consumer_name.lower(), b.filter_name.lower()),
        rank_fn=_binding_rank,
    )
    result.filters = _dedupe_best(
        result.filters,
        key_fn=lambda f: f.name.lower(),
        rank_fn=_filter_rank,
    )
    result.consumers = _dedupe_best(
        result.consumers,
        key_fn=lambda c: (c.consumer_type.lower(), c.name.lower()),
        rank_fn=_consumer_rank,
    )


def _dedupe_best(items: list, key_fn, rank_fn) -> list:
    """
    Keep one item per key, preferring the richest artefact when duplicates exist.
    """
    best_by_key: dict = {}
    key_order: list = []

    for item in items:
        key = key_fn(item)
        if key not in best_by_key:
            best_by_key[key] = item
            key_order.append(key)
            continue

        if rank_fn(item) > rank_fn(best_by_key[key]):
            best_by_key[key] = item

    return [best_by_key[k] for k in key_order]


def _state_rank(state: RecoveredState) -> int:
    if state == RecoveredState.ACTIVE:
        return 3
    if state == RecoveredState.DELETED_RECOVERED:
        return 2
    if state == RecoveredState.CARVED:
        return 1
    return 0


def _binding_rank(binding: FilterToConsumerBinding) -> tuple[int, float, int, int]:
    return (
        int(bool(binding.namespace)),
        binding.confidence,
        int(binding.encoding == DataEncoding.UTF16LE),
        _state_rank(binding.recovered_state),
    )


def _filter_rank(event_filter: EventFilter) -> tuple[int, int, int, float, int]:
    return (
        int(bool(event_filter.query)),
        int(bool(event_filter.namespace)),
        int(event_filter.encoding == DataEncoding.UTF16LE),
        event_filter.confidence,
        _state_rank(event_filter.recovered_state),
    )


def _consumer_rank(consumer: EventConsumer) -> tuple[int, int, int, float, int]:
    return (
        _consumer_detail_score(consumer),
        int(bool(consumer.namespace)),
        int(consumer.encoding == DataEncoding.UTF16LE),
        consumer.confidence,
        _state_rank(consumer.recovered_state),
    )


def _consumer_detail_score(consumer: EventConsumer) -> int:
    if isinstance(consumer, CommandLineEventConsumer):
        return int(bool(consumer.command_line_template)) + int(bool(consumer.executable_path))
    if isinstance(consumer, ActiveScriptEventConsumer):
        return (2 * int(bool(consumer.script_text))) + int(bool(consumer.scripting_engine))
    if isinstance(consumer, NTEventLogEventConsumer):
        return int(bool(consumer.source_name)) + int(consumer.event_id is not None)
    if isinstance(consumer, LogFileEventConsumer):
        return int(bool(consumer.filename)) + int(bool(consumer.text))
    if isinstance(consumer, SMTPEventConsumer):
        return (
            int(bool(consumer.smtp_server))
            + int(bool(consumer.to_line))
            + int(bool(consumer.subject))
        )
    return 0
