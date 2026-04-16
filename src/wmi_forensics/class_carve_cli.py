"""
wmi-class-carve — keyword-focused class/context carving for OBJECTS.DATA.

Example:
    wmi-class-carve -i ./Perseverance --find Win32_MemoryArrayDevice -C 10
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .class_carver import carve_class_context, render_hits_json, render_hits_text
from .cli import resolve_input


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wmi-class-carve",
        description=(
            "Keyword-focused class/context carver for WMI OBJECTS.DATA.\n"
            "Equivalent workflow to class-carve + grep -C."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "-i", "--input", required=True, metavar="PATH",
        help=(
            "OBJECTS.DATA file, or a directory that contains it "
            "(Repository folder or parent path)"
        ),
    )
    p.add_argument(
        "--find", "-q", required=True, metavar="TEXT",
        help="Keyword to search (example: Win32_MemoryArrayDevice)",
    )
    p.add_argument(
        "-C", "--context", type=int, default=10, metavar="N",
        help="Context lines around each matching string (default: 10)",
    )
    p.add_argument(
        "--window-bytes", type=int, default=65_536, metavar="N",
        help="Bytes before/after each hit to inspect (default: 65536)",
    )
    p.add_argument(
        "--max-hits", type=int, default=20, metavar="N",
        help="Maximum number of hit blocks to report (default: 20)",
    )
    p.add_argument(
        "--min-string-len", type=int, default=6, metavar="N",
        help="Minimum extracted string length (default: 6)",
    )
    p.add_argument(
        "-f", "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    p.add_argument(
        "-o", "--output", metavar="FILE", default=None,
        help="Write report to FILE (default: stdout)",
    )
    p.add_argument("-v", "--verbose", action="store_true", default=False,
                   help="Enable debug logging")
    return p


def main() -> int:
    args = _build_parser().parse_args()

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

    output_path = Path(args.output) if args.output else None
    print(f"  OBJECTS.DATA : {objects_path}", file=sys.stderr)
    print(f"  Find         : {args.find}", file=sys.stderr)

    try:
        hits = carve_class_context(
            objects_path,
            args.find,
            context_lines=max(0, args.context),
            window_bytes=max(512, args.window_bytes),
            max_hits=max(1, args.max_hits),
            min_string_len=max(3, args.min_string_len),
        )

        if args.format == "json":
            report = render_hits_json(objects_path, args.find, hits)
        else:
            report = render_hits_text(objects_path, args.find, hits)

        if output_path:
            output_path.write_text(report, encoding="utf-8")
            print(f"  Report written to {output_path}", file=sys.stderr)
        else:
            print(report)

    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        logging.exception("Unexpected error during class carving")
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())

