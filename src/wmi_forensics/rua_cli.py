"""
wmi-rua — recover SCCM CCM_RecentlyUsedApps software-execution records from a
WMI OBJECTS.DATA file.

Example:
    wmi-rua -i /evidence/Repository
    wmi-rua -i /evidence/Repository -f xlsx -o rua.xlsx
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .ccm_rua import carve_ccm_rua, render_rua_text, render_rua_xlsx
from .cli import resolve_input
from .output import default_report_path


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wmi-rua",
        description=(
            "Recover SCCM CCM_RecentlyUsedApps records (software execution "
            "evidence) from a WMI OBJECTS.DATA file."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "-i", "--input", required=True, metavar="PATH",
        help="OBJECTS.DATA file, or a directory that contains it",
    )
    p.add_argument("-f", "--format", choices=["txt", "xlsx"], default="txt",
                   dest="output_format",
                   help="Output format (default: txt). xlsx requires -o FILE.")
    p.add_argument("-o", "--output", metavar="FILE", default=None,
                   help="Write report to FILE (default: stdout)")
    p.add_argument("--max-records", type=int, default=0, metavar="N",
                   help="Cap the number of records reported (0 = unlimited)")
    p.add_argument("-v", "--verbose", action="store_true", default=False,
                   help="Enable debug logging")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s  %(name)s  %(message)s",
        stream=sys.stderr,
    )

    try:
        objects_path, _ = resolve_input(Path(args.input))
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    output_path = (Path(args.output) if args.output
                   else default_report_path(objects_path, "rua", "xlsx")
                   if args.output_format == "xlsx" else None)

    print(f"  OBJECTS.DATA : {objects_path}", file=sys.stderr)

    try:
        records = carve_ccm_rua(objects_path, max_records=max(0, args.max_records))
        print(f"  Found: {len(records)} CCM_RecentlyUsedApps record(s)", file=sys.stderr)

        if args.output_format == "xlsx":
            output_path.write_bytes(render_rua_xlsx(objects_path, records))
            print(f"  Report written to {output_path}", file=sys.stderr)
        else:
            report = render_rua_text(objects_path, records)
            if output_path:
                output_path.write_text(report, encoding="utf-8")
                print(f"  Report written to {output_path}", file=sys.stderr)
            else:
                print(report)

    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        logging.exception("Unexpected error during CCM_RUA carving")
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
