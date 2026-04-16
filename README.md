# WMI Forensics — v2.0

Offline forensic analysis of WMI/CIM repository files for DFIR investigations.

Detects **FilterToConsumerBinding persistence** artefacts — active, deleted,
and carved — with documented, explainable risk scoring.  
Works entirely offline against acquired evidence; never executes recovered content.

---

## What it detects

| Artefact type | Coverage |
|---|---|
| `__FilterToConsumerBinding` | Full (key path extraction, ASCII + UTF-16LE) |
| `__EventFilter` (name + WQL query) | Full |
| `CommandLineEventConsumer` | Full (command line, executable path) |
| `ActiveScriptEventConsumer` | Full (script text, scripting engine) |
| `NTEventLogEventConsumer` | Partial (source name, event ID) |
| `LogFileEventConsumer` | Partial (filename, text template) |
| `SMTPEventConsumer` | Partial (SMTP server, To, Subject) |
| Deleted / recovered artefacts | Yes — pages marked free in MAPPING*.MAP |
| Orphaned filters / consumers | Yes — reported separately |
| Non-standard namespaces | Detected and flagged |

---

## Installation

```bash
# From the repository root:
pip install -e ".[dev]"
```

Python 3.11+ required.  No external dependencies for the core tool.

---

## Usage

```bash
# Text report to stdout (most common)
wmi-persistence -i /evidence/OBJECTS.DATA

# JSON report for SIEM/automation
wmi-persistence -i OBJECTS.DATA -f json -o report.json

# Include known-legitimate Microsoft bindings
wmi-persistence -i OBJECTS.DATA --include-legitimate

# Only show high-risk findings (score ≥ 0.6)
wmi-persistence -i OBJECTS.DATA --min-risk 0.6

# Provide mapping file explicitly (enables deleted-artefact labelling)
wmi-persistence -i OBJECTS.DATA -m MAPPING1.MAP

# Verbose debug logging (writes to stderr)
wmi-persistence -i OBJECTS.DATA -v
```

### Where to find OBJECTS.DATA

```
C:\Windows\System32\wbem\Repository\OBJECTS.DATA          # Vista+
C:\Windows\System32\wbem\Repository\FS\OBJECTS.DATA       # XP / legacy
```

Acquire with your standard forensic imaging workflow.  The tool reads the
file read-only; it never writes to the evidence.

### Mapping files (optional but recommended)

```
C:\Windows\System32\wbem\Repository\MAPPING1.MAP
C:\Windows\System32\wbem\Repository\MAPPING2.MAP
```

If MAPPING*.MAP is present in the same directory as OBJECTS.DATA, it is
auto-detected.  Supply it explicitly with `-m` if it is elsewhere.  
Without a mapping file every artefact is labelled `recovered_state: unknown`.

---

## Output formats

### Text (default)

Human-readable, colour-coded by risk level.  Each binding shows:
- Risk score and level with full factor breakdown
- Binding details (consumer name, filter name, namespace, file offset)
- Filter details (WQL query, namespace)
- Consumer details (command line / script text / etc.)
- Parse warnings where extraction was incomplete

### JSON

Stable schema suitable for SIEM ingestion, Splunk, Elastic, or custom
pipelines.  Top-level structure:

```json
{
  "scan_metadata": { "tool", "version", "scan_timestamp", "objects_data_path" },
  "summary": { "total_bundles", "critical", "high", "medium", "low",
               "orphaned_filters", "orphaned_consumers" },
  "bundles": [ ... ],
  "orphaned_filters": [ ... ],
  "orphaned_consumers": [ ... ]
}
```

Each bundle includes `artifact_id`, `risk_score`, `risk_level`, full binding /
filter / consumer objects with offsets and `recovered_state`, and
`detection_reasons` (list of `{factor, contribution, explanation}`).

### CSV / TSV

Tab-separated.  One row per binding.  Useful for Excel triage.

```bash
wmi-persistence -i OBJECTS.DATA -f csv -o triage.tsv
```

---

## Risk scoring

Scores are **additive** and **capped at 1.0**.  Every contribution is named
and explained.

| Level | Score range | Interpretation |
|---|---|---|
| Low | 0.0 – 0.29 | Likely legitimate or informational |
| Medium | 0.3 – 0.59 | Warrants manual investigation |
| High | 0.6 – 0.79 | Unusual; probable offensive use |
| Critical | 0.8 – 1.0 | Strong structural indicators |

**This is a triage score, not a verdict.**  An analyst must always confirm
findings by reviewing the raw evidence.

### Risk factors

| Factor | Contribution | Reason |
|---|---|---|
| `active_script_consumer` | +0.50 | Executes arbitrary VBScript/JScript |
| `command_line_consumer` | +0.30 | Executes arbitrary command |
| `smtp_consumer` | +0.25 | Possible exfiltration/C2 notification |
| `lolbin_in_command` | +0.20 | Uses living-off-the-land binary |
| `download_in_command` | +0.20 | Network/download indicators in command |
| `base64_in_command` | +0.20 | Encoded command content |
| `base64_in_script` | +0.20 | Encoded content in script text |
| `download_in_script` | +0.15 | Network indicators in script |
| `non_standard_namespace` | +0.15 | Not `root\subscription` |
| `unknown_consumer_type` | +0.15 | Non-standard consumer class |
| `broad_query` | +0.10 | WQL query has no WHERE clause |
| `short_timer_interval` | +0.10 | Timer < 60 seconds |
| `artefact_from_deleted_region` | +0.10 | Found in free page (was deleted) |
| `orphaned_binding` | +0.10 | Filter or consumer not resolved |
| `suspicious_path_in_command` | +0.10 | %TEMP%, %APPDATA%, etc. |
| `missing_consumer` | +0.10 | Consumer not found |
| `missing_filter` | +0.10 | Filter not found |
| `ntevtlog_consumer` | +0.05 | Low-risk consumer type |
| `logfile_consumer` | +0.05 | Low-risk consumer type |
| `no_query_extracted` | +0.05 | WQL query could not be extracted |
| `unknown_namespace` | +0.05 | Namespace not determined |

### Known-legitimate whitelist

These bindings are present on clean Windows systems and score 0.0:

| Consumer | Filter | Note |
|---|---|---|
| BVTConsumer | BVTFilter | Microsoft BVT validation suite |
| SCM Event Log Consumer | SCM Event Log Filter | Service Control Manager |
| MSFT_SCMEventLogConsumer | MSFT_SCMEventLogFilter | SCM variant naming |

---

## Architecture

```
OBJECTS.DATA  ──►  binary_reader  ──►  carver  ──►  correlator  ──►  heuristics  ──►  reporter
                   (page I/O)         (pattern      (link           (risk            (text /
                   MAPPING*.MAP        matching)     artefacts)       scoring)         JSON /
                   allocation                                                          CSV)
                   labelling
```

### Encoding strategy

WMI stores data in two encoding contexts:

1. **ASCII** — Object key paths (B-tree index region).  Reliable anchor for
   binding detection.  Used in Phase A of the carver.

2. **UTF-16LE** — String property values (WQL queries, command lines, script
   text).  Used in Phase B.  Decoded with `errors='replace'`; replacement
   characters (U+FFFD) are filtered from extracted strings.

The carver searches for both encodings at every chunk boundary.

---

## Running tests

```bash
pip install -e ".[dev]"
pytest
```

Tests use synthetic binary fixtures — no real OBJECTS.DATA required.

---

## Forensic precision notes

### What improved over the original

| Issue | Original | This version |
|---|---|---|
| Python version | Python 2 only | Python 3.11+ |
| Binary handling | str/bytes confusion | Strict bytes throughout |
| File reading | Line-by-line (meaningless for binary) | Page-aware + overlapping chunk scan |
| Consumer coverage | CommandLine only (partially) | All 5 standard types |
| Offset tracking | None | Every artefact has file offset |
| Encoding | ASCII only | ASCII + UTF-16LE |
| Deleted artefacts | Theoretical (untested) | Explicit MAPPING*.MAP integration |
| Orphan detection | None | Filters and consumers reported separately |
| Risk scoring | Hard-coded BVT/SCM check | Documented multi-factor scoring |
| Output formats | Text only | Text + JSON + CSV |
| Error handling | Crashes on bad input | Logged, continues scan |

### What remains heuristic

- **Name extraction** — regex-based, not full WMI binary object parser.
  Names containing characters outside `\w`, `-`, `.`, `@` may be truncated.
- **WQL query extraction** — looks for `SELECT … FROM …` patterns in the
  decoded context window; may miss queries stored in unusual encodings or
  across page boundaries (>3 KB from the class name anchor).
- **Property values for CommandLine/ActiveScript** — extracted from the UTF-16LE
  context; may be incomplete if property data is far from the class name.
- **Deleted artefact detection** — depends on mapping file accuracy; if the
  mapping file itself is corrupt or missing, allocation state is UNKNOWN.

### Potential false negatives

- Bindings whose names contain characters the regex doesn't match.
- Artefacts stored in non-standard encodings.
- Artefacts that span two non-overlapping chunks (overlap is 8 KB).
- Persistent objects stored in namespaces other than `root\subscription`
  where the class name does not appear near the property data.

### Potential false positives

- Strings matching consumer/filter patterns in unrelated data (e.g. residual
  log data, hibernation files mixed with the OBJECTS.DATA content).
- Legitimate third-party WMI consumers that happen to match LOLBIN or
  download indicator patterns.
- Test/development artefacts that match binding patterns.

**Always confirm findings in hex before drawing conclusions.**  The `offset`
field in every artefact lets you jump directly to the source bytes.

---

## Legacy tools

The original Python 2 scripts are preserved in `legacy/` for reference:

- `legacy/PyWMIPersistenceFinder.py` — original binding finder
- `legacy/CCM_RUA_Finder.py` — SCCM RecentlyUsedApps extractor

They are not maintained and will not run on Python 3.

---

## License

MIT — see source files for full text.

Original work by David Pany (Mandiant/FireEye) 2017.  
Modernised and extended for Python 3 / DFIR use 2024–2025.
