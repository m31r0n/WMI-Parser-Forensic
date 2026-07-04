"""
Minimal, dependency-free XLSX writer (Office Open XML / SpreadsheetML).

An .xlsx file is just a ZIP of XML parts, so this is built with the standard
library only (``zipfile`` + string templates) — no openpyxl, keeping the
zero-install workflow intact.

Capabilities kept deliberately small but enough for forensic reports:
  * multiple worksheets
  * a bold, frozen header row
  * automatic (capped) column widths
  * strings, ints, floats, bools, None
  * long values preserved up to Excel's hard 32 767-char per-cell limit

Usage:
    write_workbook(Path("report.xlsx"), [
        Sheet("Findings", ["Name", "Score"], [["evil.exe", 0.9], ["ok.exe", 0.1]]),
    ])
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

# Excel limits.
_MAX_CELL_CHARS = 32_767
_MAX_SHEET_NAME = 31
_MAX_COL_WIDTH = 90.0
_MIN_COL_WIDTH = 8.0

_INVALID_SHEET_CHARS = set(r'[]:*?/\ ')


@dataclass
class Sheet:
    name: str
    headers: Sequence[str]
    rows: Sequence[Sequence[Any]]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_workbook(path: Path, sheets: Sequence[Sheet]) -> None:
    """Write *sheets* to an .xlsx file at *path*."""
    path.write_bytes(workbook_bytes(sheets))


def workbook_bytes(sheets: Sequence[Sheet]) -> bytes:
    """Return the full .xlsx file as bytes (used by write_workbook and tests)."""
    import io

    sheets = list(sheets) or [Sheet("Sheet1", [], [])]
    used_names = _dedupe_names([_safe_sheet_name(s.name) for s in sheets])

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _content_types(len(sheets)))
        zf.writestr("_rels/.rels", _root_rels())
        zf.writestr("xl/workbook.xml", _workbook_xml(used_names))
        zf.writestr("xl/_rels/workbook.xml.rels", _workbook_rels(len(sheets)))
        zf.writestr("xl/styles.xml", _styles_xml())
        for i, sheet in enumerate(sheets, start=1):
            zf.writestr(f"xl/worksheets/sheet{i}.xml", _worksheet_xml(sheet))
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# XML parts
# ---------------------------------------------------------------------------

def _content_types(sheet_count: int) -> str:
    overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.'
        'spreadsheetml.worksheet+xml"/>'
        for i in range(1, sheet_count + 1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        f"{overrides}"
        "</Types>"
    )


def _root_rels() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )


def _workbook_xml(names: Sequence[str]) -> str:
    sheets = "".join(
        f'<sheet name="{_attr(name)}" sheetId="{i}" r:id="rId{i}"/>'
        for i, name in enumerate(names, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{sheets}</sheets></workbook>"
    )


def _workbook_rels(sheet_count: int) -> str:
    rels = "".join(
        f'<Relationship Id="rId{i}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{i}.xml"/>'
        for i in range(1, sheet_count + 1)
    )
    styles_id = sheet_count + 1
    rels += (
        f'<Relationship Id="rId{styles_id}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f"{rels}</Relationships>"
    )


def _styles_xml() -> str:
    # cellXfs index 0 = normal, index 1 = bold (header).
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
        '<fills count="1"><fill><patternFill patternType="none"/></fill></fills>'
        '<borders count="1"><border/></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="2">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
        "</cellXfs>"
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        "</styleSheet>"
    )


def _worksheet_xml(sheet: Sheet) -> str:
    headers = list(sheet.headers)
    rows = [list(r) for r in sheet.rows]
    col_count = max([len(headers)] + [len(r) for r in rows] + [1])

    widths = _column_widths(headers, rows, col_count)
    cols_xml = (
        "<cols>"
        + "".join(
            f'<col min="{i + 1}" max="{i + 1}" width="{widths[i]:.2f}" customWidth="1"/>'
            for i in range(col_count)
        )
        + "</cols>"
    )

    body: list[str] = []
    row_index = 1
    if headers:
        body.append(_row_xml(row_index, headers, col_count, style=1))
        row_index += 1
    for row in rows:
        body.append(_row_xml(row_index, row, col_count, style=0))
        row_index += 1

    freeze = ""
    if headers:
        freeze = (
            '<sheetViews><sheetView workbookViewId="0">'
            '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
            '<selection pane="bottomLeft" activeCell="A2" sqref="A2"/>'
            "</sheetView></sheetViews>"
        )

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"{freeze}{cols_xml}"
        f"<sheetData>{''.join(body)}</sheetData></worksheet>"
    )


def _row_xml(row_number: int, values: Sequence[Any], col_count: int, style: int) -> str:
    cells: list[str] = []
    for c in range(col_count):
        value = values[c] if c < len(values) else None
        cells.append(_cell_xml(_cell_ref(c, row_number), value, style))
    return f'<row r="{row_number}">{"".join(cells)}</row>'


def _cell_xml(ref: str, value: Any, style: int) -> str:
    s_attr = f' s="{style}"' if style else ""

    if value is None or value == "":
        return f'<c r="{ref}"{s_attr}/>'

    if isinstance(value, bool):
        return f'<c r="{ref}"{s_attr}><v>{1 if value else 0}</v></c>'

    if isinstance(value, (int, float)):
        return f'<c r="{ref}"{s_attr}><v>{value}</v></c>'

    text = _clip(str(value))
    return (
        f'<c r="{ref}"{s_attr} t="inlineStr">'
        f'<is><t xml:space="preserve">{_text(text)}</t></is></c>'
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _column_widths(headers, rows, col_count) -> list[float]:
    widths = [_MIN_COL_WIDTH] * col_count
    all_rows = ([headers] if headers else []) + list(rows)
    for row in all_rows:
        for c in range(min(len(row), col_count)):
            length = len(str(row[c])) if row[c] is not None else 0
            widths[c] = max(widths[c], min(float(length) + 2.0, _MAX_COL_WIDTH))
    return widths


def _cell_ref(col_index: int, row_number: int) -> str:
    return f"{_col_letter(col_index)}{row_number}"


def _col_letter(index: int) -> str:
    letters = ""
    index += 1
    while index > 0:
        index, rem = divmod(index - 1, 26)
        letters = chr(65 + rem) + letters
    return letters


def _clip(text: str) -> str:
    if len(text) <= _MAX_CELL_CHARS:
        return text
    marker = " …[truncated to Excel's 32767-char cell limit; full value in the .txt report]"
    return text[: _MAX_CELL_CHARS - len(marker)] + marker


def _text(value: str) -> str:
    """Escape XML text and strip characters illegal in XML 1.0."""
    cleaned = []
    for ch in value:
        o = ord(ch)
        if ch in ("\t", "\n", "\r") or o >= 0x20:
            cleaned.append(ch)
        else:
            cleaned.append(".")
    escaped = "".join(cleaned)
    return escaped.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _attr(value: str) -> str:
    return _text(value).replace('"', "&quot;")


def _safe_sheet_name(name: str) -> str:
    cleaned = "".join("_" if ch in _INVALID_SHEET_CHARS else ch for ch in name).strip()
    cleaned = cleaned or "Sheet"
    return cleaned[:_MAX_SHEET_NAME]


def _dedupe_names(names: list[str]) -> list[str]:
    seen: dict[str, int] = {}
    out: list[str] = []
    for name in names:
        if name not in seen:
            seen[name] = 1
            out.append(name)
        else:
            seen[name] += 1
            suffix = f"_{seen[name]}"
            out.append(name[: _MAX_SHEET_NAME - len(suffix)] + suffix)
    return out
