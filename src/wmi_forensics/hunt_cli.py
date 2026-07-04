"""
wmi-hunt — discover WMI classes that hide an embedded payload in a property
default value (Base64 + inflate/gzip → PE/.NET/script/…), without needing the
class name. Fileless "class as storage" technique (MITRE T1546.003).

Example:
    wmi-hunt -i /evidence/Repository
    wmi-hunt -i /evidence/Repository --dump -f xlsx
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .class_carver import (
    dump_hunt_payloads,
    hunt_payload_classes,
    render_hunt_text,
    render_hunt_xlsx,
)
from .cli import resolve_input
from .output import default_dump_dir, default_report_path


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wmi-hunt",
        description=(
            "Hunt WMI class properties for embedded payloads (fileless storage)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-i", "--input", required=True, metavar="PATH",
                   help="OBJECTS.DATA file, or a directory that contains it")
    p.add_argument("--dump", metavar="DIR", nargs="?", const="", default=None,
                   help="Extract discovered payloads to DIR (default: a folder "
                        "next to the evidence)")
    p.add_argument("--max-hits", type=int, default=500, metavar="N",
                   help="Cap the number of payloads reported (default: 500)")
    p.add_argument("-f", "--format", choices=["txt", "xlsx"], default="txt",
                   help="Output format (default: txt). xlsx is written next to "
                        "the evidence unless -o is given.")
    p.add_argument("-o", "--output", metavar="FILE", default=None,
                   help="Write report to FILE")
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
                   else default_report_path(objects_path, "hunt", "xlsx") if args.format == "xlsx"
                   else None)

    print(f"  OBJECTS.DATA : {objects_path}", file=sys.stderr)

    try:
        hits = hunt_payload_classes(objects_path, max_hits=max(1, args.max_hits))
        print(f"  Found: {len(hits)} class-stored payload(s)", file=sys.stderr)

        if args.dump is not None and hits:
            dump_dir = Path(args.dump) if args.dump else default_dump_dir(objects_path, "hunt")
            written = dump_hunt_payloads(hits, dump_dir)
            print(f"  Dumped       : {len(written)} payload(s) to {dump_dir}", file=sys.stderr)

        if args.format == "xlsx":
            output_path.write_bytes(render_hunt_xlsx(objects_path, hits))
            print(f"  Report written to {output_path}", file=sys.stderr)
        else:
            report = render_hunt_text(objects_path, hits)
            if output_path:
                output_path.write_text(report, encoding="utf-8")
                print(f"  Report written to {output_path}", file=sys.stderr)
            else:
                print(report)

    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        logging.exception("Unexpected error during hunt")
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
