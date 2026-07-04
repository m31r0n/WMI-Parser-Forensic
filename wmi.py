#!/usr/bin/env python3
"""
WMI Forensics — zero-install launcher.

Run the toolkit straight from the source tree, no ``pip install`` required:

    python wmi.py <mode> [options]

Modes:
    persistence   Detect and risk-score WMI event-subscription persistence
                  (FilterToConsumerBinding / EventFilter / EventConsumer).
                  This is the default mode if none is given.
    carve         Structured decode of a class definition (or raw strings),
                  with optional payload decode/extraction (--decode/--dump).
    rua           Recover SCCM CCM_RecentlyUsedApps records (software
                  execution evidence: path, launch count, last-used, user).
    hunt          Auto-discover classes hiding an embedded payload in a
                  property value (fileless storage, MITRE T1546.003).

Examples:
    python wmi.py persistence -i /evidence/Repository -f xlsx
    python wmi.py carve -i /evidence/Repository --find Win32_Process --decode
    python wmi.py rua -i /evidence/Repository -f xlsx
    python wmi.py hunt -i /evidence/Repository --dump -f xlsx

Get the options for a mode with -h:
    python wmi.py persistence -h
    python wmi.py carve -h
    python wmi.py rua -h
    python wmi.py hunt -h

The classic command names (wmi-persistence / wmi-class-carve) are also
available after an optional ``pip install -e .``; this launcher needs neither.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the package importable directly from src/ without installation.
_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from wmi_forensics.class_carve_cli import main as carve_main  # noqa: E402
from wmi_forensics.cli import main as persistence_main  # noqa: E402
from wmi_forensics.hunt_cli import main as hunt_main  # noqa: E402
from wmi_forensics.rua_cli import main as rua_main  # noqa: E402

_MODES = {
    "persistence": persistence_main,
    "carve": carve_main,
    "rua": rua_main,
    "hunt": hunt_main,
    # Convenience aliases
    "class-carve": carve_main,
    "p": persistence_main,
    "c": carve_main,
    "r": rua_main,
    "h": hunt_main,
}


def main() -> int:
    argv = sys.argv[1:]

    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    # First token selects the mode; everything after it is forwarded verbatim.
    if argv and argv[0] in _MODES:
        return _MODES[argv[0]](argv[1:])

    # No recognised mode -> default to persistence and forward all arguments,
    # so `python wmi.py -i ...` still works.
    return persistence_main(argv)


if __name__ == "__main__":
    sys.exit(main())
