"""Tests for CLI input resolution (file vs directory)."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from wmi_forensics.cli import _build_parser, main, resolve_input


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


class TestClassModeCli:
    def test_parser_accepts_class_mode_args(self):
        p = _build_parser()
        args = p.parse_args([
            "-i", "OBJECTS.DATA",
            "--class-find", "Win32_MemoryArrayDevice",
            "-C", "5",
            "--class-max-hits", "3",
        ])
        assert args.class_find == "Win32_MemoryArrayDevice"
        assert args.context == 5
        assert args.class_max_hits == 3

    def test_main_class_mode_text(self, tmp_path, monkeypatch, capsys):
        od = _make_od(tmp_path)
        od.write_bytes(
            b"header\x00Win32_MemoryArrayDevice\x00\x00payload\x00\x00"
        )
        monkeypatch.setattr(
            "sys.argv",
            ["wmi-persistence", "-i", str(od), "--class-find", "Win32_MemoryArrayDevice", "-C", "2"],
        )
        rc = main()
        out = capsys.readouterr().out
        assert rc == 0
        assert "WMI Class Carver" in out
        assert "Win32_MemoryArrayDevice" in out

    def test_main_class_mode_rejects_csv(self, tmp_path, monkeypatch):
        od = _make_od(tmp_path)
        monkeypatch.setattr(
            "sys.argv",
            ["wmi-persistence", "-i", str(od), "--class-find", "Win32_MemoryArrayDevice", "-f", "csv"],
        )
        rc = main()
        assert rc == 2
