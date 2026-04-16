"""
Page-aware binary reader for WMI OBJECTS.DATA files.

OBJECTS.DATA is divided into 8 192-byte pages (Vista+).
MAPPING1/2.MAP records the logical→physical page mapping and which pages are
free (deleted content).  Pairing both files lets us label recovered artefacts
as DELETED_RECOVERED vs ACTIVE.  When no mapping file is available every page
is reported as UNKNOWN.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .models import RecoveredState

logger = logging.getLogger(__name__)

WMI_PAGE_SIZE = 0x2000  # 8 192 bytes (Vista+)

_MAP_HEADER_SIZE = 16   # uint32 × 4: version, first_id, second_id, free_count
_MAP_ENTRY_SIZE  = 4    # uint32 per logical page entry; 0xFFFFFFFF = free


@dataclass
class PageInfo:
    page_number: int
    file_offset: int
    is_allocated: bool | None   # None = mapping file not available
    page_data: bytes

    @property
    def recovered_state(self) -> RecoveredState:
        if self.is_allocated is None:
            return RecoveredState.UNKNOWN
        return RecoveredState.ACTIVE if self.is_allocated else RecoveredState.DELETED_RECOVERED


class WMIBinaryReader:
    def __init__(
        self,
        objects_path: Path,
        mapping_path: Path | None = None,
        page_size: int = WMI_PAGE_SIZE,
    ) -> None:
        self.objects_path = objects_path
        self.page_size = page_size
        self._allocation_map: dict[int, bool] = {}
        self._mapping_loaded = False

        if mapping_path is not None:
            self._load_mapping(mapping_path)

    def _load_mapping(self, mapping_path: Path) -> None:
        """Parse MAPPING*.MAP and populate the page allocation table."""
        try:
            data = mapping_path.read_bytes()
        except OSError as exc:
            logger.warning("Cannot read mapping file %s: %s", mapping_path, exc)
            return

        if len(data) < _MAP_HEADER_SIZE:
            logger.warning("Mapping file too small (%d bytes), skipping", len(data))
            return

        version, first_id, second_id, free_count = struct.unpack_from("<IIII", data, 0)
        logger.debug(
            "Mapping: version=%d first_id=%d second_id=%d free_pages=%d",
            version, first_id, second_id, free_count,
        )

        entries_bytes = data[_MAP_HEADER_SIZE:]
        for logical_page in range(len(entries_bytes) // _MAP_ENTRY_SIZE):
            (physical_page,) = struct.unpack_from("<I", entries_bytes, logical_page * _MAP_ENTRY_SIZE)
            if physical_page == 0xFFFFFFFF:
                self._allocation_map[logical_page] = False
            else:
                self._allocation_map[physical_page] = True

        self._mapping_loaded = True
        logger.info("Loaded mapping: %d entries", len(self._allocation_map))

    def _page_allocated(self, page_number: int) -> bool | None:
        if not self._mapping_loaded:
            return None
        return self._allocation_map.get(page_number)

    def iter_pages(self) -> Iterator[PageInfo]:
        """Yield every page in OBJECTS.DATA in file order."""
        file_size = self.objects_path.stat().st_size
        page_count = (file_size + self.page_size - 1) // self.page_size

        with self.objects_path.open("rb") as fh:
            for page_number in range(page_count):
                page_data = fh.read(self.page_size)
                if not page_data:
                    break
                yield PageInfo(
                    page_number=page_number,
                    file_offset=page_number * self.page_size,
                    is_allocated=self._page_allocated(page_number),
                    page_data=page_data,
                )

    def iter_chunks(
        self,
        chunk_size: int = 65_536,
        overlap: int = 8_192,
    ) -> Iterator[tuple[int, bytes]]:
        """
        Yield (file_offset, chunk_bytes) with overlap so artefacts that span
        chunk boundaries are not missed.  Used by the carver.
        """
        file_size = self.objects_path.stat().st_size
        offset = 0

        with self.objects_path.open("rb") as fh:
            while offset < file_size:
                fh.seek(offset)
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                yield offset, chunk
                if len(chunk) < chunk_size:
                    break
                offset += chunk_size - overlap

    def allocation_state_at(self, file_offset: int) -> RecoveredState:
        page_number = file_offset // self.page_size
        allocated = self._page_allocated(page_number)
        if allocated is None:
            return RecoveredState.UNKNOWN
        return RecoveredState.ACTIVE if allocated else RecoveredState.DELETED_RECOVERED


def find_mapping_file(objects_path: Path) -> Path | None:
    """Return the most recently modified MAPPING*.MAP next to OBJECTS.DATA."""
    candidates = list(objects_path.parent.glob("MAPPING*.MAP"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)
