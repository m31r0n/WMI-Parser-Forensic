"""
wmi-persistence — offline forensic analysis of WMI OBJECTS.DATA files.

Examples:
    wmi-persistence -i OBJECTS.DATA
    wmi-persistence -i OBJECTS.DATA -f json -o report.json
    wmi-persistence -i OBJECTS.DATA -m MAPPING1.MAP --min-risk 0.6
    wmi-persistence -i OBJECTS.DATA --include-legitimate --no-colour
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .carver import WMICarver
from .correlator import WMICorrelator
from .heuristics import score_bundle
from .reporter import write_report


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wmi-persistence",
        description="Offline forensic analysis of WMI OBJECTS.DATA files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-i", "--input", required=True, metavar="OBJECTS.DATA",
                   help="Path to OBJECTS.DATA")
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

    objects_path = Path(args.input)
    if not objects_path.is_file():
        print(f"ERROR: Input file not found: {objects_path}", file=sys.stderr)
        return 1

    mapping_path = Path(args.mapping) if args.mapping else None
    output_path  = Path(args.output) if args.output else None

    print(f"  Scanning {objects_path} ...", file=sys.stderr)

    try:
        carver = WMICarver(objects_path, mapping_path=mapping_path)
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
