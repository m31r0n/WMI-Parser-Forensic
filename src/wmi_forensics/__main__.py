"""
Allow running the persistence scanner as a module:

    python -m wmi_forensics -i /evidence/Repository

This mirrors the ``wmi-persistence`` console script created on install.
The class carver stays available at ``python -m wmi_forensics.class_carve_cli``.
"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
