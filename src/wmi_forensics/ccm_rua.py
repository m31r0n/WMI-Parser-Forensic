"""
CCM RecentlyUsedApplication (RUA) carver for the WMI repository.

SCCM software metering records per-application usage as
``CCM_RecentlyUsedApps`` class instances inside ``OBJECTS.DATA`` (or the
extracted ``C:\\Windows\\CCM\\InventoryStore.sdf``). Each record is strong
evidence of **software execution**: full file path, launch count, last-used
time, and the user who ran it — even for programs long since deleted.

Three on-disk formats are recovered:

    vista_full / xp_full  null-delimited record preceded by a binary header
                          (two FILETIMEs, file size, launch count). The GUID
                          in the header identifies the OS family.
    carved                null-delimited body whose header was overwritten or
                          fell outside the recovered region — no timestamps.
    xml                   XML-serialised record.

This is a modernised, bytes-safe reimplementation of the original
``CCM_RUA_Finder.py`` (David Pany, Mandiant/FireEye, 2017). It replaces the
fragile 50-byte chunked seeking with a single regex pass, adds length guards
around the binary header, and emits typed :class:`CCMRecentlyUsedApp` records
for text / JSON / CSV reporting.

Reference: FLARE, "Windows Management Instrumentation (WMI) Offense, Defense,
and Forensics".
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

from .models import CCMRecentlyUsedApp
from .xlsx_writer import Sheet, workbook_bytes

logger = logging.getLogger(__name__)

# GUIDs that head a CCM_RUA instance, stored as UTF-16LE text in the header.
_GUID_VISTA = (
    "7C261551B264D35E30A7FA29C75283DAE04BBA71DBE8F5E553F7AD381B406DD8"
    .encode("utf-16-le")
)
_GUID_XP = "6FA62F462BEF740F820D72D9250D743C".encode("utf-16-le")

# latin-1 views of the GUIDs (1:1 byte<->char) for searching the decoded blob.
_GUID_VISTA_S = _GUID_VISTA.decode("latin-1")
_GUID_XP_S = _GUID_XP.decode("latin-1")

# Binary header layout, measured from the end of the GUID:
#   timestamp_1  <Q  @ 0
#   timestamp_2  <Q  @ 8
#   unused (34)      @ 16
#   file_size    <L  @ 50
#   unused (20)      @ 54
#   launch_count <L  @ 74
_HEADER_MIN_LEN = 78
_HEADER_LOOKBACK = 300

# Field order of the null-delimited body, after "CCM_RecentlyUsedApps\x00\x00".
_NULL_FIELDS = [
    "additional_product_codes", "company_name", "explorer_file_name",
    "file_description", "file_properties_hash", "file_version", "folder_path",
    "last_used_time", "last_user_name", "msi_display_name", "msi_publisher",
    "msi_version", "original_file_name", "product_language", "product_name",
    "product_version", "software_properties_hash",
]

_NULL_RE = re.compile(
    "CCM_RecentlyUsedApps\x00\x00"
    + "\x00\x00".join(f"(?P<{name}>[^\x00]*)" for name in _NULL_FIELDS)
)

_XML_RE = re.compile(
    r"<CCM_RecentlyUsedApps><AdditionalProductCodes>"
    r"(?P<additional_product_codes>.*?)</AdditionalProductCodes>"
    r"<CompanyName>(?P<company_name>.*?)</CompanyName>"
    r"<ExplorerFileName>(?P<explorer_file_name>.*?)</ExplorerFileName>"
    r"<FileDescription>(?P<file_description>.*?)</FileDescription>"
    r"<FilePropertiesHash>(?P<file_properties_hash>.*?)</FilePropertiesHash>"
    r"<FileSize>(?P<file_size>.*?)</FileSize>"
    r"<FileVersion>(?P<file_version>.*?)</FileVersion>"
    r"<FolderPath>(?P<folder_path>.*?)</FolderPath>"
    r"<LastUsedTime>(?P<last_used_time>.*?)</LastUsedTime>"
    r"<LastUserName>(?P<last_user_name>.*?)</LastUserName>"
    r"<msiDisplayName>(?P<msi_display_name>.*?)</msiDisplayName>"
    r"<msiPublisher>(?P<msi_publisher>.*?)</msiPublisher>"
    r"<msiVersion>(?P<msi_version>.*?)</msiVersion>"
    r"<OriginalFileName>(?P<original_file_name>.*?)</OriginalFileName>"
    r"<ProductCode>(?P<product_code>.*?)</ProductCode>"
    r"<ProductLanguage>(?P<product_language>.*?)</ProductLanguage>"
    r"<ProductName>(?P<product_name>.*?)</ProductName>"
    r"<ProductVersion>(?P<product_version>.*?)</ProductVersion>"
    r"<SoftwarePropertiesHash>(?P<software_properties_hash>.*?)"
    r"</SoftwarePropertiesHash></CCM_RecentlyUsedApps>",
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def carve_ccm_rua(objects_path: Path, *, max_records: int = 0) -> list[CCMRecentlyUsedApp]:
    """
    Recover CCM_RecentlyUsedApps records from *objects_path*.

    *max_records* > 0 caps the number of records returned (0 = unlimited).
    Duplicate carvings of the same (path, file, last-used) tuple are collapsed,
    preferring the richest record (one that carries a header).
    """
    data = objects_path.read_bytes()
    # latin-1 keeps a 1:1 byte<->char mapping, so regex match positions are
    # also byte offsets and header bytes round-trip via .encode("latin-1").
    text = data.decode("latin-1")
    file_path = str(objects_path)

    best: dict[tuple[str, str, str], CCMRecentlyUsedApp] = {}
    order: list[tuple[str, str, str]] = []

    def keep(rec: CCMRecentlyUsedApp | None) -> None:
        if rec is None:
            return
        key = (rec.folder_path.lower(), rec.explorer_file_name.lower(), rec.last_used_time)
        existing = best.get(key)
        if existing is None:
            best[key] = rec
            order.append(key)
        elif _richness(rec) > _richness(existing):
            best[key] = rec

    for m in _NULL_RE.finditer(text):
        keep(_build_null_record(text, m, file_path))
    for m in _XML_RE.finditer(text):
        keep(_build_xml_record(m, file_path))

    records = [best[k] for k in order]
    records.sort(key=lambda r: r.last_used_time, reverse=True)
    if max_records > 0:
        records = records[:max_records]
    logger.info("Recovered %d CCM_RUA record(s)", len(records))
    return records


# ---------------------------------------------------------------------------
# Record builders
# ---------------------------------------------------------------------------

def _build_null_record(text: str, m: re.Match, file_path: str) -> CCMRecentlyUsedApp | None:
    g = {name: _clean(m.group(name)) for name in _NULL_FIELDS}
    if _is_schema_noise(g):
        return None

    last_used, tz = _normalise_time(g["last_used_time"])
    record_format, ts1, ts2, file_size, launch_count = _parse_header(text, m.start())

    rec = CCMRecentlyUsedApp(
        explorer_file_name=g["explorer_file_name"],
        folder_path=g["folder_path"],
        last_used_time=last_used,
        last_user_name=g["last_user_name"],
        launch_count=launch_count,
        file_size=file_size,
        file_description=g["file_description"],
        company_name=g["company_name"],
        product_name=g["product_name"],
        product_version=g["product_version"],
        file_version=g["file_version"],
        original_file_name=g["original_file_name"],
        msi_display_name=g["msi_display_name"],
        msi_publisher=g["msi_publisher"],
        msi_version=g["msi_version"],
        product_language=g["product_language"],
        additional_product_codes=g["additional_product_codes"],
        file_properties_hash=g["file_properties_hash"],
        software_properties_hash=g["software_properties_hash"],
        time_zone_offset=tz,
        timestamp_1=ts1,
        timestamp_2=ts2,
        record_format=record_format,
        offset=m.start(),
        file_path=file_path,
    )
    if not (rec.explorer_file_name or rec.folder_path or rec.original_file_name):
        return None
    return rec


def _build_xml_record(m: re.Match, file_path: str) -> CCMRecentlyUsedApp | None:
    g = {k: _clean(v) for k, v in m.groupdict().items()}
    last_used, tz = _normalise_time(g["last_used_time"])
    try:
        file_size = int(g["file_size"]) if g["file_size"].isdigit() else None
    except ValueError:
        file_size = None

    rec = CCMRecentlyUsedApp(
        explorer_file_name=g["explorer_file_name"],
        folder_path=g["folder_path"].replace("\\\\", "\\"),
        last_used_time=last_used,
        last_user_name=g["last_user_name"].replace("\\\\", "\\"),
        file_size=file_size,
        file_description=g["file_description"],
        company_name=g["company_name"],
        product_name=g["product_name"],
        product_version=g["product_version"],
        file_version=g["file_version"],
        original_file_name=g["original_file_name"],
        msi_display_name=g["msi_display_name"],
        msi_publisher=g["msi_publisher"],
        msi_version=g["msi_version"],
        product_code=g["product_code"],
        product_language=g["product_language"],
        additional_product_codes=g["additional_product_codes"],
        file_properties_hash=g["file_properties_hash"],
        software_properties_hash=g["software_properties_hash"],
        time_zone_offset=tz,
        record_format="xml",
        offset=m.start(),
        file_path=file_path,
    )
    if not (rec.explorer_file_name or rec.folder_path or rec.original_file_name):
        return None
    return rec


# ---------------------------------------------------------------------------
# Header / field helpers
# ---------------------------------------------------------------------------

def _parse_header(
    text: str, body_start: int
) -> tuple[str, str, str, int | None, int | None]:
    """
    Look back from the record body for a GUID header and decode it.

    Returns (record_format, timestamp_1, timestamp_2, file_size, launch_count).
    Falls back to ("carved", "", "", None, None) when no header is present.
    """
    window_start = max(0, body_start - _HEADER_LOOKBACK)
    window = text[window_start:body_start]

    for guid_s, fmt in ((_GUID_VISTA_S, "vista_full"), (_GUID_XP_S, "xp_full")):
        idx = window.rfind(guid_s)
        if idx == -1:
            continue
        header = window[idx + len(guid_s):].encode("latin-1")
        if len(header) < _HEADER_MIN_LEN:
            break
        ts1 = _filetime(struct.unpack_from("<Q", header, 0)[0])
        ts2 = _filetime(struct.unpack_from("<Q", header, 8)[0])
        file_size = struct.unpack_from("<L", header, 50)[0]
        launch_count = struct.unpack_from("<L", header, 74)[0]
        return fmt, ts1, ts2, file_size, launch_count

    return "carved", "", "", None, None


def _filetime(qword: int) -> str:
    """Convert a Windows FILETIME (100-ns ticks since 1601-01-01) to a string."""
    if qword == 0:
        return ""
    try:
        dt = datetime(1601, 1, 1) + timedelta(microseconds=qword / 10)
    except (OverflowError, OSError, ValueError):
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _normalise_time(raw: str) -> tuple[str, str]:
    """Turn a CIM datetime like ``20170320143025.000000+000`` into a readable
    timestamp plus the trailing UTC-minutes offset."""
    raw = raw.strip()
    if len(raw) >= 14 and raw[:14].isdigit():
        d = raw
        readable = f"{d[:4]}-{d[4:6]}-{d[6:8]} {d[8:10]}:{d[10:12]}:{d[12:14]}"
        tz = raw[-4:] if len(raw) >= 4 else ""
        return readable, tz
    return raw, ""


def _clean(value: str | None) -> str:
    if not value:
        return ""
    return (
        value.replace("\\x0020", " ")
        .replace("&#174;", "(R)")
        .strip()
    )


def _is_schema_noise(fields: dict[str, str]) -> bool:
    """The CIM class definition itself matches the body regex, with the field
    *values* being the property *names*. Reject those."""
    return (
        fields["explorer_file_name"].lower() in ("explorerfilename", "")
        and fields["company_name"].lower() in ("companyname", "")
        and fields["folder_path"].lower() in ("folderpath", "")
    ) or fields["additional_product_codes"].lower().startswith("additionalproductcode")


def _richness(rec: CCMRecentlyUsedApp) -> int:
    return (
        int(rec.launch_count is not None)
        + int(bool(rec.timestamp_1))
        + int(bool(rec.last_used_time))
        + int(bool(rec.last_user_name))
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "record_format", "folder_path", "explorer_file_name", "original_file_name",
    "file_size", "launch_count", "last_used_time", "time_zone_offset",
    "last_user_name", "timestamp_1", "timestamp_2", "file_description",
    "company_name", "product_name", "product_version", "file_version",
    "msi_display_name", "msi_publisher", "msi_version", "product_code",
    "product_language", "additional_product_codes", "file_properties_hash",
    "software_properties_hash", "offset",
]


def render_rua_text(objects_path: Path, records: list[CCMRecentlyUsedApp]) -> str:
    out: list[str] = []
    out.append("=" * 72)
    out.append("  CCM RecentlyUsedApps — Software Execution Report")
    out.append("=" * 72)
    out.append("")
    out.append(f"  OBJECTS.DATA : {objects_path}")
    out.append(f"  Records      : {len(records)}")

    if not records:
        out.append("")
        out.append("  No CCM_RecentlyUsedApps records found.")
        out.append("=" * 72)
        return "\n".join(out)

    for i, r in enumerate(records, start=1):
        out.append("")
        out.append("-" * 72)
        out.append(f"  [{i}] {r.display_name()}")
        out.append("-" * 72)
        out.append(f"    Last used   : {r.last_used_time or '(unknown)'}"
                   + (f"  (tz {r.time_zone_offset})" if r.time_zone_offset else ""))
        out.append(f"    Launch count: {r.launch_count if r.launch_count is not None else '(unknown)'}")
        out.append(f"    File size   : {r.file_size if r.file_size is not None else '(unknown)'}")
        out.append(f"    Last user   : {r.last_user_name or '(unknown)'}")
        if r.file_description or r.company_name:
            out.append(f"    Description : {r.file_description}  [{r.company_name}]")
        if r.product_name or r.product_version:
            out.append(f"    Product     : {r.product_name} {r.product_version}".rstrip())
        if r.timestamp_1 or r.timestamp_2:
            out.append(f"    Header time : {r.timestamp_1 or '-'} / {r.timestamp_2 or '-'}")
        out.append(f"    Format      : {r.record_format}   offset=0x{r.offset:08X}")

    out.append("")
    out.append("=" * 72)
    return "\n".join(out)


def render_rua_xlsx(objects_path: Path, records: list[CCMRecentlyUsedApp]) -> bytes:
    """Return a workbook: an executive Summary sheet + the full records sheet."""
    fmts = {}
    for r in records:
        fmts[r.record_format] = fmts.get(r.record_format, 0) + 1
    dated = [r.last_used_time for r in records if r.last_used_time]
    users = sorted({r.last_user_name for r in records if r.last_user_name})

    summary_rows = [
        ["Report", "SCCM CCM_RecentlyUsedApps (software execution)"],
        ["OBJECTS.DATA", str(objects_path)],
        ["Records recovered", len(records)],
        ["By format", ", ".join(f"{k}={v}" for k, v in sorted(fmts.items())) or "(none)"],
        ["Earliest last-used", min(dated) if dated else ""],
        ["Latest last-used", max(dated) if dated else ""],
        ["Distinct users", ", ".join(users[:20]) + ("…" if len(users) > 20 else "")],
        ["Meaning", "Each record is evidence a program executed (path, launch "
                    "count, last-used time, user) — including deleted programs."],
    ]
    record_rows = []
    for r in records:
        d = asdict(r)
        record_rows.append([d.get(col) for col in _CSV_COLUMNS])
    sheets = [
        Sheet("Summary", ["Field", "Value"], summary_rows),
        Sheet("CCM_RecentlyUsedApps", _CSV_COLUMNS, record_rows),
    ]
    return workbook_bytes(sheets)
