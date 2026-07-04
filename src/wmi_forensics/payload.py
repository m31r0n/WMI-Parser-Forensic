"""
Decode and identify payloads hidden in WMI class-property default values.

A common fileless technique (MITRE T1546.003 storage) stores an executable or
script inside a WMI class property, usually **Base64 then DEFLATE-compressed**
(as seen in HTB "Perseverance": the value Base64-decodes then raw-inflates to a
.NET assembly). This module reproduces that: it tries Base64, then optional
inflate/gzip, and identifies the resulting bytes by magic number.

``decode_payload(value)`` returns a :class:`DecodedPayload` describing the
recovered content (type, size, SHA-256, decode chain, and the bytes for dumping)
or ``None`` when *value* is not a decodable payload worth surfacing.
"""

from __future__ import annotations

import base64
import hashlib
import re
import zlib
from dataclasses import dataclass, field

# (magic prefix, file_type, extension)
_MAGICS: list[tuple[bytes, str, str]] = [
    (b"MZ", "pe", "exe"),
    (b"\x7fELF", "elf", "elf"),
    (b"PK\x03\x04", "zip", "zip"),
    (b"%PDF", "pdf", "pdf"),
    (b"\xd0\xcf\x11\xe0", "ole-compound", "bin"),
    (b"\x1f\x8b\x08", "gzip", "gz"),
    (b"Rar!\x1a\x07", "rar", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7zip", "7z"),
    (b"\x89PNG\r\n", "png", "png"),
    (b"BM", "bitmap", "bmp"),
]

# File types considered "notable" for the hunt (i.e. real hidden content).
NOTABLE_TYPES = frozenset({
    "pe", ".net-assembly", "elf", "zip", "pdf", "ole-compound", "gzip",
    "rar", "7zip", "script",
})

_SCRIPT_MARKERS = (
    b"powershell", b"function ", b"cmd ", b"cscript", b"wscript", b"<script",
    b"iex", b"invoke-", b"$env:", b"import ", b"#!/", b"add-type",
)


@dataclass
class DecodedPayload:
    steps: list[str]          # e.g. ["base64", "raw-inflate"]
    file_type: str            # e.g. ".net-assembly"
    extension: str            # suggested file extension
    size: int
    sha256: str
    preview: str = ""         # short printable preview (text/scripts)
    data: bytes = field(default=b"", repr=False)  # not serialised


def decode_payload(value: str) -> DecodedPayload | None:
    """Best decode of *value* (a class-property string), or None."""
    value = value.strip()
    if len(value) < 24 or not re.fullmatch(r"[A-Za-z0-9+/=\s]+", value):
        return None
    try:
        raw = base64.b64decode(value, validate=False)
    except Exception:
        return None
    if len(raw) < 4:
        return None

    candidates: list[tuple[list[str], bytes]] = [(["base64"], raw)]
    for wbits, label in ((-15, "raw-inflate"), (47, "zlib/gzip")):
        try:
            out = zlib.decompress(raw, wbits)
            if out:
                candidates.append((["base64", label], out))
        except Exception:
            pass

    best: tuple[int, list[str], bytes, str, str] | None = None
    for steps, data in candidates:
        ftype, ext = _detect(data)
        # Prefer recognised types, and prefer decompressed results.
        score = (2 if ftype in NOTABLE_TYPES else 0) + (1 if len(steps) > 1 else 0)
        if best is None or score > best[0]:
            best = (score, steps, data, ftype, ext)

    _, steps, data, ftype, ext = best
    # Uninteresting: base64 of opaque bytes that never resolves to a known type.
    if ftype in ("binary", "text") and len(steps) == 1:
        return None

    return DecodedPayload(
        steps=steps, file_type=ftype, extension=ext, size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        preview=_preview(data) if ftype in ("script", "text") else "",
        data=data,
    )


def _detect(data: bytes) -> tuple[str, str]:
    for magic, ftype, ext in _MAGICS:
        if data.startswith(magic):
            if ftype == "pe":
                head = data[:8192]
                if b"BSJB" in data or b"mscoree" in head or b"_CorExeMain" in head \
                        or b".NETFramework" in data[:16384]:
                    return ".net-assembly", "dll"
                return "pe", "exe"
            return ftype, ext

    sample = data[:1024]
    if sample:
        printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126)
        if printable / len(sample) > 0.90:
            low = data[:8192].lower()
            if any(k in low for k in _SCRIPT_MARKERS):
                return "script", "txt"
            return "text", "txt"
    return "binary", "bin"


def _preview(data: bytes, limit: int = 200) -> str:
    text = data[:limit].decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ")
    return text + ("…" if len(data) > limit else "")
