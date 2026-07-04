# WMI Forensics — v2.1

Offline forensic analysis of WMI/CIM repository files for DFIR investigations.

Detects **FilterToConsumerBinding persistence** artefacts — active, deleted,
and carved — with documented, explainable risk scoring, and recovers
**SCCM software-execution history** (`CCM_RecentlyUsedApps`).  
Works entirely offline against acquired evidence; never executes recovered content.

---

## What it detects

**Persistence** (`persistence` mode):

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

**Software execution** (`rua` mode):

| Artefact type | Coverage |
|---|---|
| `CCM_RecentlyUsedApps` (SCCM software metering) | Full path, launch count, last-used time, user, file size, product metadata |
| Full / carved / XML record formats | Yes — deleted records recovered when the binary header survives |

**Class definitions** (`carve` mode): best-effort structured decode of CIM
class definitions (classname, properties, CIM types, full default values), with
a grep-style raw string fallback (`--raw`).

**Embedded payloads** (`hunt` mode / `carve --decode`): detect and extract
executables/scripts hidden in class property values (Base64 + inflate/gzip →
PE/.NET/ZIP/script), with SHA-256 and file-type — the fileless "class as
storage" technique (MITRE T1546.003).

---

## Installation

**None required.** Python 3.11+ and the standard library are enough — the core
tool has no third-party dependencies. Clone (or copy) the repository and run the
launcher directly:

```bash
python wmi.py persistence -i /evidence/Repository
python wmi.py carve       -i /evidence/Repository --find Win32_Process
```

`wmi.py` (at the repository root) adds `src/` to the import path for you, so it
works from any working directory with no `pip install` and no `PYTHONPATH`
setup.

### Optional: install for short command names

If you prefer `wmi-persistence` / `wmi-class-carve` on your PATH (e.g. to run
from anywhere without typing `python wmi.py`), install it editable:

```bash
pip install -e .          # add "[dev]" to also get pytest for the test suite
```

After that, these are all equivalent:

| Zero-install launcher | Installed command |
|---|---|
| `python wmi.py persistence …` | `wmi-persistence …` |
| `python wmi.py rua …` | `wmi-rua …` |
| `python wmi.py carve …` | `wmi-class-carve …` |
| `python wmi.py hunt …` | `wmi-hunt …` |

---

## Usage

The tool has four **modes**, all driven by `python wmi.py <mode>`:

| Mode | Purpose |
|---|---|
| `persistence` | Detect and score WMI event-subscription persistence (the main DFIR mode; used if no mode is given) |
| `rua` | Recover SCCM `CCM_RecentlyUsedApps` software-execution records |
| `carve` | Structured decode of a class definition (`--decode`/`--dump` to extract embedded payloads); `--raw` for the string view |
| `hunt` | Auto-discover classes hiding an embedded payload in a property value (fileless storage) |

**Where reports go:** by default, `xlsx` reports and extracted payloads are
written **next to the evidence** (the OBJECTS.DATA folder), not the tool's
directory — pass `-o` to override. Every `xlsx` opens with an **Executive
Summary** sheet followed by the technical detail sheets.

Both accept a **file** or a **directory** with `-i`. Given a directory, the
tool auto-locates `OBJECTS.DATA` (searching the folder, `Repository/`, and
`FS/`) and any adjacent `MAPPING*.MAP`.

> The examples below use the zero-install launcher `python wmi.py <mode>`.
> If you installed the package (`pip install -e .`), the installed commands
> `wmi-persistence`, `wmi-rua`, `wmi-class-carve`, and `wmi-hunt` are drop-in
> equivalents of `python wmi.py persistence` / `rua` / `carve` / `hunt` — the
> options are identical.

### Quick start

```bash
# Point at the acquired Repository folder and read the report
python wmi.py persistence -i /evidence/wbem/Repository
```

### Typical DFIR workflow

1. **Acquire** the WMI repository from the evidence (see [paths](#where-to-find-the-repository)).
   Copy the whole `Repository` folder so `OBJECTS.DATA` and `MAPPING*.MAP`
   stay together — the mapping file is what distinguishes live from deleted
   artefacts.
2. **Triage** with a text report to spot high-risk bindings quickly:
   ```bash
   python wmi.py persistence -i /evidence/wbem/Repository --min-risk 0.6
   ```
3. **Export** structured output for your case notes / SIEM:
   ```bash
   python wmi.py persistence -i /evidence/wbem/Repository -f xlsx -o wmi_findings.xlsx
   ```
4. **Confirm** each finding in a hex viewer using the `offset` field reported
   for every artefact — the score is triage, never a verdict.
5. **Carve deeper** into any suspicious class or string with the `carve` mode
   (below).

### `persistence` mode — option reference

```
python wmi.py persistence -i PATH [options]
```

| Option | Description |
|---|---|
| `-i, --input PATH` | **Required.** `OBJECTS.DATA` file, or a directory containing it (Repository folder or its parent, mounted image, etc.). |
| `-m, --mapping FILE` | `MAPPING1.MAP` / `MAPPING2.MAP`. Auto-detected next to `OBJECTS.DATA` if omitted. Enables `active` vs `deleted_recovered` labelling. |
| `-f, --format {txt,xlsx}` | Output format. Default `txt`. xlsx requires `-o FILE`. |
| `-o, --output FILE` | Write the report to `FILE` instead of stdout. |
| `--min-risk SCORE` | Only report bindings with `risk_score >= SCORE` (0.0–1.0). |
| `--include-legitimate` | Also show known-legitimate Microsoft bindings (BVT, SCM, …) that are suppressed by default. |
| `--no-colour` | Disable ANSI colour in text output (for redirection/logging). |
| `-v, --verbose` | Debug logging to stderr. |

Progress and file-resolution messages go to **stderr**; the report goes to
**stdout** (or `-o`), so piping and redirection stay clean.

```bash
# Excel report for triage
python wmi.py persistence -i OBJECTS.DATA -f xlsx -o report.xlsx

# Include known-legitimate Microsoft bindings
python wmi.py persistence -i OBJECTS.DATA --include-legitimate

# Provide the mapping file explicitly (evidence stored elsewhere)
python wmi.py persistence -i OBJECTS.DATA -m /evidence/MAPPING1.MAP
```

### `carve` mode — class definitions and keyword carving

By default `carve` produces a **best-effort structured decode** of the CIM
class definition(s) matching a keyword — classname, superclass, timestamp,
properties (name + CIM type), and full **untruncated** default/string values —
laid out similarly to FLARE `python-cim`. Use it to:

- inspect a specific WMI class definition (e.g. `Win32_Process`, a custom
  provider class, or a suspicious class name from another tool);
- recover data an attacker stashed inside a WMI class **property** default
  value (a common fileless-storage technique) — the full payload, never clipped;
- fall back to a grep-style string view (`--raw`) for markers (filenames, URLs)
  anywhere in the raw repository.

```bash
# Structured class-definition decode (default)
python wmi.py carve -i /evidence/Repository --find Win32_MemoryArrayDevice

# Excel workbook (Classes / Properties / Default Values sheets)
python wmi.py carve -i /evidence/Repository --find Win32_MemoryArrayDevice -f xlsx -o class.xlsx

# Raw string-context view (grep-like), untruncated
python wmi.py carve -i /evidence/Repository --find Win32_MemoryArrayDevice --raw -C 20
```

| Option | Description |
|---|---|
| `-i, --input PATH` | **Required.** File or directory (same resolution as `persistence` mode). |
| `--find, -q TEXT` | **Required.** Keyword / class name to decode (ASCII + UTF-16LE). |
| `--raw` | Force the raw string-context view instead of the structured decode. |
| `--decode` | Decode property default values (Base64 + inflate/gzip) and report the embedded file type + SHA-256. |
| `--dump [DIR]` | Extract decoded payloads to `DIR` (implies `--decode`; default: a folder next to the evidence). |
| `-C, --context N` | (raw view) Context lines around each match. Default `10`. |
| `--window-bytes N` | (raw view) Bytes before/after each hit to inspect. Default `65536`. |
| `--max-hits N` | Cap on definitions / hit blocks reported. Default `20`. |
| `--min-string-len N` | (raw view) Minimum extracted string length. Default `6`. |
| `-f, --format {txt,xlsx}` | Output format. Default `txt`. xlsx auto-names next to the evidence unless `-o`. |
| `-o, --output FILE` | Write to `FILE` instead of stdout / the default location. |

### `hunt` mode — find classes hiding a payload

When you **don't** know which class hides a payload, `hunt` scans the whole
repository for property values that decode to real executables/scripts and
tells you the class, property, file type, SHA-256, and timestamp:

```bash
# Discover class-stored payloads
python wmi.py hunt -i /evidence/Repository

# Extract every discovered payload and write an Excel report
python wmi.py hunt -i /evidence/Repository --dump -f xlsx
```

| Option | Description |
|---|---|
| `-i, --input PATH` | **Required.** File or directory. |
| `--dump [DIR]` | Extract discovered payloads to `DIR` (default: a folder next to the evidence). |
| `--max-hits N` | Cap the number of payloads reported. Default `500`. |
| `-f, --format {txt,xlsx}` | Output format. Default `txt`. |
| `-o, --output FILE` | Write report to `FILE`. |

> Extracted payloads are **live malware** — dumping a real sample to disk may
> trigger antivirus/EDR quarantine. Handle in an isolated analysis environment.

> **Best-effort, not a full CIM parser.** The structured decode does not read
> `INDEX.BTR` or reconstruct the full object graph, so it can miss or mislabel
> fields on damaged records and automatically falls back to the raw string view
> when it recovers no structure. For authoritative class parsing, cross-check
> with FLARE [python-cim](https://github.com/mandiant/flare-wmi). On Windows,
> the wrappers in `scripts/` run the carver through the launcher for you.

### `rua` mode — SCCM software-execution history

`CCM_RecentlyUsedApps` records are written by the SCCM software-metering agent
and stored inside the same WMI repository. Each is strong evidence that a
program **executed** — including its full path, launch count, last-used time,
and the user who ran it — and records often survive for programs that have been
deleted. Recover them with:

```bash
# Human-readable report
python wmi.py rua -i /evidence/Repository

# Excel workbook for triage / timeline building
python wmi.py rua -i /evidence/Repository -f xlsx -o rua.xlsx
```

| Option | Description |
|---|---|
| `-i, --input PATH` | **Required.** File or directory (same resolution as `persistence` mode). |
| `-f, --format {txt,xlsx}` | Output format. Default `txt`. xlsx requires `-o`. |
| `-o, --output FILE` | Write to `FILE` instead of stdout. |
| `--max-records N` | Cap the number of records reported (0 = unlimited). |

Three record formats are recovered and labelled: `vista_full` / `xp_full`
(complete records with a binary header carrying the two FILETIMEs, file size,
and launch count), `carved` (body recovered without a parseable header — no
timestamps), and `xml`. Duplicate carvings of the same application are merged,
keeping the richest record.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Completed (report produced; may contain zero findings). |
| `1` | Input not found / could not resolve `OBJECTS.DATA`. |
| `2` | Unexpected error, or an unsupported option combination. |
| `130` | Interrupted (Ctrl-C). |

### Where to find the repository

```
C:\Windows\System32\wbem\Repository\OBJECTS.DATA          # Vista+
C:\Windows\System32\wbem\Repository\FS\OBJECTS.DATA       # XP / legacy
```

Acquire with your standard forensic imaging workflow. The tool opens the file
**read-only** and never writes to the evidence.

### Mapping files (optional but recommended)

```
C:\Windows\System32\wbem\Repository\MAPPING1.MAP
C:\Windows\System32\wbem\Repository\MAPPING2.MAP
```

If a `MAPPING*.MAP` is present next to `OBJECTS.DATA` it is auto-detected (the
most recently modified one is used). Supply it explicitly with `-m` if it lives
elsewhere. Without a mapping file, allocation state cannot be determined and
every artefact is labelled `recovered_state: unknown`.

---

## Output formats

Every mode outputs **`txt`** (default, to stdout or `-o`) or **`xlsx`** (a
structured workbook, `-o FILE` required). There is no per-cell character limit
beyond Excel's own hard 32 767-char maximum; the `txt` report is never
truncated. The `.xlsx` writer is pure standard library — no dependencies, no
`pip install`.

### Text (default)

Human-readable. For `persistence`, colour-coded by risk level; each binding
shows the risk score with full factor breakdown, binding/filter/consumer
details with file offsets, and parse warnings. For `rua`, one block per record.
For `carve`, the structured class-definition view (or the raw string view with
`--raw`).

### XLSX

A multi-sheet workbook, ordered and complete, ready for triage in Excel. Header
row is bold and frozen; columns auto-size. Sheets per mode:

| Mode | Sheets |
|---|---|
| `persistence` | Summary · Bindings · Risk Factors · Orphaned Filters · Orphaned Consumers |
| `rua` | CCM_RecentlyUsedApps (one row per record) |
| `carve` | Classes · Properties · Default Values (or a single sheet in `--raw`) |

```bash
python wmi.py persistence -i /evidence/Repository -f xlsx -o findings.xlsx
python wmi.py rua         -i /evidence/Repository -f xlsx -o rua.xlsx
python wmi.py carve       -i /evidence/Repository --find Win32_Process -f xlsx -o class.xlsx
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
                   (page I/O)         (pattern      (link           (risk            (txt /
                   MAPPING*.MAP        matching)     artefacts)       scoring)         xlsx)
                   allocation
                   labelling

Side channels:  ccm_rua (SCCM RUA records) · cim (structured class decode) · xlsx_writer
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

The tool itself needs no install, but the test runner (`pytest`) is a dev
dependency:

```bash
pip install -e ".[dev]"      # one-time, for the test suite only
pytest
```

Or, without installing the package, point `pytest` at `src/`:

```bash
pip install pytest
PYTHONPATH=src pytest
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
| Output formats | Text only | Text + native XLSX (no dependencies) |
| Error handling | Crashes on bad input | Logged, continues scan |
| CCM_RUA carving | Fragile 50-byte seeking, `str < int` bug, no length guards | Single-pass regex, typed records, header length-guarded, txt/xlsx |
| Class definitions | grep + external flare-wmi | Built-in best-effort structured decode (full, untruncated values) |

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

The original Python 2 scripts are preserved in `legacy/` for reference. Both
have been reimplemented in this version — they run on neither Python 3 nor are
maintained, and are kept only for provenance:

- `legacy/PyWMIPersistenceFinder.py` — original binding finder → reimplemented
  and extended as the `persistence` mode.
- `legacy/CCM_RUA_Finder.py` — SCCM RecentlyUsedApps extractor → reimplemented
  (bytes-safe, single-pass, typed records, txt/xlsx output) as the `rua` mode.

---

## License

MIT — see [LICENSE](LICENSE).

Based on the original **WMI_Forensics** by David Pany (Mandiant/FireEye, 2017),
rewritten for Python 3 and extended for modern DFIR use.
