"""
wmi-persistence — offline forensic analysis of WMI OBJECTS.DATA files.

-i acepta un fichero OR una carpeta:
    -i OBJECTS.DATA                 fichero directo
    -i C:\\evidence\\Repository     busca OBJECTS.DATA dentro (y MAPPING*.MAP)
    -i C:\\evidence\\               busca en subcarpetas Repository/ y FS/

Examples:
    wmi-persistence -i OBJECTS.DATA
    wmi-persistence -i "C:\\Windows\\System32\\wbem\\Repository"
    wmi-persistence -i OBJECTS.DATA -f json -o report.json
    wmi-persistence -i OBJECTS.DATA -m MAPPING1.MAP --min-risk 0.6
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .carver import WMICarver
from .class_carver import carve_class_context, render_hits_json, render_hits_text
from .correlator import WMICorrelator
from .heuristics import score_bundle
from .reporter import write_report

# Candidate names for OBJECTS.DATA, in priority order
_OD_NAMES = ["OBJECTS.DATA", "objects.data"]

# Subdirectories that WMI uses on different Windows versions
_REPO_SUBDIRS = ["", "Repository", "FS"]


def resolve_input(input_path: Path) -> tuple[Path, Path | None]:
    """
    Accept either a direct OBJECTS.DATA path or a directory.

    When given a directory, searches for OBJECTS.DATA in:
        <dir>/
        <dir>/Repository/
        <dir>/FS/

    Returns (objects_data_path, mapping_path_or_None).
    Raises FileNotFoundError if nothing is found.
    """
    if input_path.is_file():
        mapping = _find_mapping(input_path.parent)
        return input_path, mapping

    if input_path.is_dir():
        for subdir in _REPO_SUBDIRS:
            candidate_dir = input_path / subdir if subdir else input_path
            for name in _OD_NAMES:
                candidate = candidate_dir / name
                if candidate.is_file():
                    mapping = _find_mapping(candidate_dir)
                    return candidate, mapping

        # List what was found to help the user
        found = list(input_path.rglob("OBJECTS.DATA")) + list(input_path.rglob("objects.data"))
        if found:
            hint = f"\n  Did you mean one of these?\n" + "\n".join(f"    {p}" for p in found[:5])
        else:
            hint = ""
        raise FileNotFoundError(
            f"OBJECTS.DATA not found under '{input_path}'.{hint}"
        )

    raise FileNotFoundError(f"Path not found: '{input_path}'")


def _find_mapping(directory: Path) -> Path | None:
    """Return the most recently modified MAPPING*.MAP in *directory*, or None."""
    candidates = list(directory.glob("MAPPING*.MAP")) + list(directory.glob("MAPPING*.map"))
    return max(candidates, key=lambda p: p.stat().st_mtime) if candidates else None


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wmi-persistence",
        description=(
            "Offline forensic analysis of WMI OBJECTS.DATA files.\n"
            "-i acepta un fichero o una carpeta (Repository, evidencia montada, etc.)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "-i", "--input", required=True, metavar="PATH",
        help=(
            "OBJECTS.DATA file, or a directory that contains it "
            "(e.g. the Repository folder or its parent)"
        ),
    )
    p.add_argument("-m", "--mapping", metavar="MAPPING.MAP", default=None,
                   help="MAPPING1.MAP or MAPPING2.MAP (auto-detected if omitted)")
    p.add_argument("-f", "--format", choices=["text", "json", "csv"], default="text",
                   dest="output_format", help="Output format (default: text)")
    p.add_argument("-o", "--output", metavar="FILE", default=None,
                   help="Write report to FILE (default: stdout)")
    p.add_argument("--include-legitimate", action="store_true", default=False,
                   help="Include known-legitimate Microsoft bindings")
    p.add_argument("--min-risk", type=float, default=0.0, metavar="SCORE",
                   help="Only report bindings with risk_score >= SCORE (0.0-1.0)")
    p.add_argument("--no-colour", action="store_true", default=False,
                   help="Disable ANSI colour in text output")
    p.add_argument("--class-find", metavar="TEXT", default=None,
                   help="Class/keyword carving mode (example: Win32_MemoryArrayDevice)")
    p.add_argument("-C", "--context", type=int, default=10, metavar="N",
                   help="Context lines around class keyword hits (default: 10)")
    p.add_argument("--class-window-bytes", type=int, default=65536, metavar="N",
                   help="Bytes before/after each class hit to inspect (default: 65536)")
    p.add_argument("--class-max-hits", type=int, default=20, metavar="N",
                   help="Maximum class hit blocks to report (default: 20)")
    p.add_argument("--class-min-string-len", type=int, default=6, metavar="N",
                   help="Minimum extracted string length in class mode (default: 6)")
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
        objects_path, auto_mapping = resolve_input(Path(args.input))
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # Explicit -m overrides auto-detected mapping
    mapping_path = Path(args.mapping) if args.mapping else auto_mapping
    output_path  = Path(args.output) if args.output else None

    print(f"  OBJECTS.DATA : {objects_path}", file=sys.stderr)
    if args.class_find:
        print(f"  Class find   : {args.class_find}", file=sys.stderr)
    else:
        if mapping_path:
            print(f"  Mapping file : {mapping_path}", file=sys.stderr)
        else:
            print("  Mapping file : not found (allocation state will be UNKNOWN)", file=sys.stderr)

    try:
        if args.class_find:
            if args.output_format not in ("text", "json"):
                print("ERROR: class mode supports only -f text or -f json", file=sys.stderr)
                return 2

            hits = carve_class_context(
                objects_path,
                args.class_find,
                context_lines=max(0, args.context),
                window_bytes=max(512, args.class_window_bytes),
                max_hits=max(1, args.class_max_hits),
                min_string_len=max(3, args.class_min_string_len),
            )

            report = (
                render_hits_json(objects_path, args.class_find, hits)
                if args.output_format == "json"
                else render_hits_text(objects_path, args.class_find, hits)
            )

            if output_path:
                output_path.write_text(report, encoding="utf-8")
                print(f"  Report written to {output_path}", file=sys.stderr)
            else:
                print(report)
            return 0

        carver = WMICarver(objects_path, mapping_path=mapping_path, auto_find_mapping=False)
        carver_result = carver.scan()

        print(
            f"  Found: {len(carver_result.bindings)} binding(s), "
            f"{len(carver_result.filters)} filter(s), "
            f"{len(carver_result.consumers)} consumer(s)",
            file=sys.stderr,
        )

        correlator = WMICorrelator(carver_result)
        correlation_result = correlator.correlate()

        for bundle in correlation_result.bundles:
            score_bundle(bundle)

        use_colour = not args.no_colour and sys.stdout.isatty()
        report = write_report(
            correlation_result,
            fmt=args.output_format,
            output_file=output_path,
            objects_path=objects_path,
            mapping_path=mapping_path,
            include_legitimate=args.include_legitimate,
            min_risk_score=args.min_risk,
            use_colour=use_colour,
        )

        if output_path:
            print(f"  Report written to {output_path}", file=sys.stderr)
        else:
            print(report)

    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        logging.exception("Unexpected error during scan")
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
