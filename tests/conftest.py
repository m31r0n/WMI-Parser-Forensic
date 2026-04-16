"""Shared fixtures for WMI forensics tests.

All fixtures produce synthetic binary data — no real OBJECTS.DATA required.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Byte-level builders
# ---------------------------------------------------------------------------

def _pad(data: bytes, page_size: int = 8192) -> bytes:
    rem = len(data) % page_size
    return data + b"\x00" * (page_size - rem) if rem else data


def make_binding_ascii(
    consumer_type: str = "CommandLineEventConsumer",
    consumer_name: str = "evil_consumer",
    filter_name: str = "evil_filter",
) -> bytes:
    """ASCII-encoded binding key path as it appears in the B-tree index."""
    return (
        f'_FilterToConsumerBinding'
        f'{consumer_type}.Name="{consumer_name}"'
        f'_EventFilter.Name="{filter_name}"'
    ).encode("ascii")


def make_consumer_utf16le(
    class_name: str = "CommandLineEventConsumer",
    consumer_name: str = "evil_consumer",
    command: str = "cmd.exe /c evil.bat",
) -> bytes:
    return f'{class_name}.Name="{consumer_name}" CommandLineTemplate="{command}" '.encode("utf-16-le")


# ---------------------------------------------------------------------------
# File fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_objects_data(tmp_path: Path) -> Path:
    """Minimal OBJECTS.DATA with a legitimate BVT binding, a suspicious
    CommandLine binding, an ActiveScript binding, and UTF-16LE consumer data."""
    chunks = [
        _pad(make_binding_ascii("CommandLineEventConsumer", "BVTConsumer", "BVTFilter") + b"\x00" * 64),
        _pad(
            make_binding_ascii("CommandLineEventConsumer", "backdoor_consumer", "trigger_filter")
            + b"\x00" * 64
            + b'__EventFilter.Name="trigger_filter"\x00\x00SELECT * FROM __InstanceCreationEvent'
            + b"\x00" * 32
        ),
        _pad(make_binding_ascii("ActiveScriptEventConsumer", "script_consumer", "trigger_filter") + b"\x00" * 64),
        _pad(make_consumer_utf16le("CommandLineEventConsumer", "backdoor_consumer", "powershell.exe -enc AAABBBCCC==")),
    ]
    od = tmp_path / "OBJECTS.DATA"
    od.write_bytes(b"".join(chunks))
    return od


@pytest.fixture
def tmp_objects_data_empty(tmp_path: Path) -> Path:
    od = tmp_path / "OBJECTS.DATA"
    od.write_bytes(b"\x00" * 8192)
    return od


@pytest.fixture
def tmp_mapping_file(tmp_path: Path) -> Path:
    """MAPPING1.MAP with pages 0,1,3 allocated and page 2 free."""
    header  = struct.pack("<IIII", 1, 1001, 1002, 1)
    entries = struct.pack("<IIII", 0, 1, 0xFFFFFFFF, 3)
    mf = tmp_path / "MAPPING1.MAP"
    mf.write_bytes(header + entries)
    return mf
