"""Tests for the payload decoder (base64 + inflate/gzip + file-type detection)."""

from __future__ import annotations

import base64
import gzip
import zlib

from wmi_forensics.payload import decode_payload


def _raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


_DOTNET = b"MZ\x90\x00" + bytes((i * 37 + 11) % 256 for i in range(400)) + b"BSJB" + b"payload"


class TestDecode:
    def test_base64_plus_raw_inflate_dotnet(self):
        value = _b64(_raw_deflate(_DOTNET))
        d = decode_payload(value)
        assert d is not None
        assert d.file_type == ".net-assembly"
        assert d.steps == ["base64", "raw-inflate"]
        assert d.extension == "dll"
        assert d.size == len(_DOTNET)

    def test_plain_pe_not_compressed(self):
        pe = b"MZ\x90\x00" + bytes((i * 13) % 256 for i in range(300))
        d = decode_payload(_b64(pe))
        assert d is not None
        assert d.file_type in ("pe", ".net-assembly")
        assert d.steps == ["base64"]

    def test_gzip_wrapped(self):
        raw = b"MZ\x90\x00" + bytes((i * 7 + 3) % 256 for i in range(300))
        value = _b64(gzip.compress(raw))
        d = decode_payload(value)
        assert d is not None
        assert d.file_type in ("pe", ".net-assembly")
        assert "zlib/gzip" in d.steps

    def test_script_payload(self):
        script = b"powershell -nop -w hidden -enc " + b"A" * 300
        d = decode_payload(_b64(_raw_deflate(script)))
        assert d is not None
        assert d.file_type == "script"
        assert d.preview

    def test_zip_payload(self):
        zip_bytes = b"PK\x03\x04" + bytes((i * 5) % 256 for i in range(300))
        d = decode_payload(_b64(zip_bytes))
        assert d is not None
        assert d.file_type == "zip"

    def test_sha256_matches(self):
        import hashlib
        value = _b64(_raw_deflate(_DOTNET))
        d = decode_payload(value)
        assert d.sha256 == hashlib.sha256(_DOTNET).hexdigest()


class TestNonPayload:
    def test_random_base64_returns_none(self):
        opaque = _b64(bytes((i * 191 + 7) % 256 for i in range(400)))
        assert decode_payload(opaque) is None

    def test_short_or_nonbase64_returns_none(self):
        assert decode_payload("hello") is None
        assert decode_payload("not base64 @#$%") is None
        assert decode_payload("") is None
