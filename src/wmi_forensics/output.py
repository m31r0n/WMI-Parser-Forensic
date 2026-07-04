"""
Report/output path resolution.

By default, reports and extracted payloads are written **next to the evidence**
(the folder that contains OBJECTS.DATA), not the tool's working directory, so an
analyst's artefacts stay with the case. An explicit ``-o`` always wins.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def default_report_path(objects_path: Path, mode: str, ext: str) -> Path:
    """`<evidence folder>/wmi_<mode>_<UTCstamp>.<ext>`."""
    return objects_path.parent / f"wmi_{mode}_{_stamp()}.{ext}"


def default_dump_dir(objects_path: Path, mode: str) -> Path:
    """`<evidence folder>/wmi_<mode>_payloads_<UTCstamp>/`."""
    return objects_path.parent / f"wmi_{mode}_payloads_{_stamp()}"


def resolve_report_path(explicit: str | None, objects_path: Path, mode: str, ext: str) -> Path:
    return Path(explicit) if explicit else default_report_path(objects_path, mode, ext)
