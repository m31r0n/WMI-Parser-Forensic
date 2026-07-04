"""
wmi_forensics — offline forensic analysis of WMI/CIM repositories.

Core layers
-----------
binary_reader : page-aware I/O with optional MAPPING*.MAP allocation state
carver        : pattern-based artifact extraction (ASCII + UTF-16LE)
correlator    : link bindings ↔ filters ↔ consumers; detect orphans
heuristics    : documented, explainable risk scoring
reporter      : text / native XLSX output

Capabilities
------------
cli          : `persistence` mode — event-subscription persistence
ccm_rua      : `rua` mode — SCCM CCM_RecentlyUsedApps (software execution)
cim          : `carve` mode — best-effort structured class-definition decode
payload      : Base64 + inflate/gzip decode and file-type identification
class_carver : carve rendering + `hunt` (auto-discover class-stored payloads)
xlsx_writer  : dependency-free XLSX writer
output       : report/payload paths (default: next to the evidence)
"""

__version__ = "2.1.0"
