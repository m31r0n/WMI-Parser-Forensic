"""
wmi-class-carve — keyword-focused class/context carving for OBJECTS.DATA.

Example:
    wmi-class-carve -i /evidence/Repository --find Win32_MemoryArrayDevice -C 10
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .class_carver import (
    carve_class_context,
    carve_class_structured,
    dump_payloads,
    render_hits_text,
    render_hits_xlsx,
    render_structured_text,
    render_structured_xlsx,
)
from .cli import resolve_input
from .output import default_dump_dir, default_report_path


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
        "--raw", action="store_true", default=False,
        help="Force the raw string-context view instead of the structured "
             "class-definition decode",
    )
    p.add_argument(
        "--decode", action="store_true", default=False,
        help="Decode property default values (Base64 + inflate/gzip) and report "
             "the embedded file type (PE/.NET/script/…)",
    )
    p.add_argument(
        "--dump", metavar="DIR", nargs="?", const="", default=None,
        help="Extract decoded payloads to DIR (implies --decode; default: a "
             "folder next to the evidence)",
    )
    p.add_argument(
        "-f", "--format", choices=["txt", "xlsx"], default="txt",
        help="Output format (default: txt). xlsx is written next to the "
             "evidence unless -o is given.",
    )
    p.add_argument(
        "-o", "--output", metavar="FILE", default=None,
        help="Write report to FILE (txt default: stdout; xlsx default: next to evidence)",
    )
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

    decode = args.decode or args.dump is not None
    output_path = (Path(args.output) if args.output
                   else default_report_path(objects_path, "carve", "xlsx") if args.format == "xlsx"
                   else None)

    print(f"  OBJECTS.DATA : {objects_path}", file=sys.stderr)
    print(f"  Find         : {args.find}", file=sys.stderr)

    try:
        views = [] if args.raw else carve_class_structured(
            objects_path, args.find, max_views=max(1, args.max_hits), decode=decode
        )

        if views:
            mode = "structured"
            if args.dump is not None:
                dump_dir = Path(args.dump) if args.dump else default_dump_dir(objects_path, "carve")
                written = dump_payloads(views, dump_dir)
                print(f"  Dumped       : {len(written)} payload(s) to {dump_dir}", file=sys.stderr)
            report_bytes = (render_structured_xlsx(objects_path, args.find, views)
                            if args.format == "xlsx" else None)
            report_text = (None if args.format == "xlsx"
                           else render_structured_text(objects_path, args.find, views))
        else:
            mode = "raw"
            if not args.raw:
                print("  Structured decode found nothing; using raw string view.",
                      file=sys.stderr)
            hits = carve_class_context(
                objects_path,
                args.find,
                context_lines=max(0, args.context),
                window_bytes=max(512, args.window_bytes),
                max_hits=max(1, args.max_hits),
                min_string_len=max(3, args.min_string_len),
            )
            report_bytes = (render_hits_xlsx(objects_path, args.find, hits)
                            if args.format == "xlsx" else None)
            report_text = (None if args.format == "xlsx"
                           else render_hits_text(objects_path, args.find, hits))

        print(f"  View         : {mode}", file=sys.stderr)
        if args.format == "xlsx":
            output_path.write_bytes(report_bytes)
            print(f"  Report written to {output_path}", file=sys.stderr)
        elif output_path:
            output_path.write_text(report_text, encoding="utf-8")
            print(f"  Report written to {output_path}", file=sys.stderr)
        else:
            print(report_text)

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

