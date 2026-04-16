"""Tests for CLI input resolution (file vs directory)."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from wmi_forensics.cli import resolve_input


def _make_od(directory: Path, name: str = "OBJECTS.DATA") -> Path:
    od = directory / name
    od.write_bytes(b"\x00" * 8192)
    return od


def _make_mapping(directory: Path) -> Path:
    mf = directory / "MAPPING1.MAP"
    mf.write_bytes(struct.pack("<IIII", 1, 0, 0, 0))
    return mf


class TestResolveInput:
    def test_direct_file(self, tmp_path):
        od = _make_od(tmp_path)
        result, mapping = resolve_input(od)
        assert result == od

    def test_direct_file_finds_mapping(self, tmp_path):
        od = _make_od(tmp_path)
        mf = _make_mapping(tmp_path)
        _, mapping = resolve_input(od)
        assert mapping == mf

    def test_direct_file_no_mapping(self, tmp_path):
        od = _make_od(tmp_path)
        _, mapping = resolve_input(od)
        assert mapping is None

    def test_directory_root(self, tmp_path):
        """OBJECTS.DATA directly inside the given directory."""
        od = _make_od(tmp_path)
        result, _ = resolve_input(tmp_path)
        assert result == od

    def test_directory_repository_subdir(self, tmp_path):
        """OBJECTS.DATA inside <dir>/Repository/ (Vista+ layout)."""
        repo = tmp_path / "Repository"
        repo.mkdir()
        od = _make_od(repo)
        result, _ = resolve_input(tmp_path)
        assert result == od

    def test_directory_fs_subdir(self, tmp_path):
        """OBJECTS.DATA inside <dir>/FS/ (XP legacy layout)."""
        fs = tmp_path / "FS"
        fs.mkdir()
        od = _make_od(fs)
        result, _ = resolve_input(tmp_path)
        assert result == od

    def test_directory_mapping_auto_detected(self, tmp_path):
        repo = tmp_path / "Repository"
        repo.mkdir()
        _make_od(repo)
        mf = _make_mapping(repo)
        _, mapping = resolve_input(tmp_path)
        assert mapping == mf

    def test_directory_not_found_raises(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(FileNotFoundError):
            resolve_input(empty)

    def test_nonexistent_path_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            resolve_input(tmp_path / "doesnotexist")

    def test_lowercase_objects_data(self, tmp_path):
        """Case-insensitive filename match."""
        od = _make_od(tmp_path, name="objects.data")
        result, _ = resolve_input(tmp_path)
        assert result == od
