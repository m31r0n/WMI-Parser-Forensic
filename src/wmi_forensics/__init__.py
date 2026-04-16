"""
wmi_forensics — offline forensic analysis of WMI/CIM repositories.

Layers
------
binary_reader : page-aware I/O with optional MAPPING*.MAP support
carver        : pattern-based artifact extraction (ASCII + UTF-16LE)
correlator    : link bindings ↔ filters ↔ consumers; detect orphans
heuristics    : documented, explainable risk scoring
reporter      : text / JSON / CSV output
cli           : entry point
class_carver  : keyword-focused class/context carving
"""

__version__ = "2.0.0"
