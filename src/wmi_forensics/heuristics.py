"""
Risk scoring for WMI persistence artefacts.

Scores are additive and capped at 1.0.  Every contribution is named and
explained so an analyst can understand and challenge each decision.
The whitelist covers known-legitimate Microsoft internal bindings.

This is a triage score, not a verdict.  An analyst must confirm findings.

Risk levels:
    0.0–0.29  low      likely legitimate or informational
    0.3–0.59  medium   warrants manual investigation
    0.6–0.79  high     unusual; probable offensive use
    0.8–1.0   critical strong structural indicators of hostile persistence
"""

from __future__ import annotations

import re

from .models import (
    ActiveScriptEventConsumer,
    CommandLineEventConsumer,
    EventConsumer,
    EventFilter,
    FilterToConsumerBinding,
    LogFileEventConsumer,
    NTEventLogEventConsumer,
    RecoveredState,
    RiskDetail,
    SMTPEventConsumer,
    WMIPersistenceBundle,
)

# ---------------------------------------------------------------------------
# Known-legitimate bindings (consumer_name_lower, filter_name_lower)
# ---------------------------------------------------------------------------

_KNOWN_LEGITIMATE: dict[tuple[str, str], str] = {
    ("bvtconsumer",              "bvtfilter"):              "Microsoft built-in BVT validation binding",
    ("scm event log consumer",   "scm event log filter"):   "Service Control Manager event log binding",
    ("msft_scmeventlogconsumer", "msft_scmeventlogfilter"): "SCM event log binding (variant naming)",
    ("ntevtlogconsumer",         "ntevtlogfilter"):          "WMI internal NT event log binding",
}

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_LOLBINS = re.compile(
    r"\b(cmd|powershell|pwsh|wscript|cscript|mshta|regsvr32|rundll32|"
    r"certutil|bitsadmin|msiexec|wmic|schtasks|at\.exe|"
    r"installutil|regasm|regsvcs|odbcconf|ieexec)\b",
    re.IGNORECASE,
)
_DOWNLOAD = re.compile(
    r"(https?://|ftp://|\\\\|\bWebClient\b|\bInvoke-WebRequest\b|"
    r"\bDownloadString\b|\bDownloadFile\b|\biwr\b|\bcurl\b|\bwget\b)",
    re.IGNORECASE,
)
_BASE64_BLOCK = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_FROMBASE64   = re.compile(r"FromBase64String|EncodedCommand|enc\s+[A-Za-z0-9+/]{20,}", re.IGNORECASE)
_TEMP_PATHS   = re.compile(
    r"(%TEMP%|%APPDATA%|%PUBLIC%|\\Temp\\|\\AppData\\|\\Users\\Public\\|"
    r"C:\\Windows\\Temp|C:\\ProgramData\\)",
    re.IGNORECASE,
)
_TIMER_RE     = re.compile(r"TimerInterval\s*[<>=]+\s*(\d+)", re.IGNORECASE)
_STANDARD_NS  = re.compile(r"^root\\subscription", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def score_bundle(bundle: WMIPersistenceBundle) -> WMIPersistenceBundle:
    """Compute and attach risk_score / risk_level / detection_reasons in place."""
    reasons: list[RiskDetail] = []

    if _is_known_legitimate(bundle):
        bundle.is_known_legitimate = True
        bundle.risk_score = 0.0
        bundle.risk_level = "low"
        bundle.detection_reasons = reasons
        return bundle

    score = 0.0
    score, reasons = _score_consumer(bundle.consumer, score, reasons)
    score, reasons = _score_filter(bundle.event_filter, score, reasons)
    score, reasons = _score_structural(bundle, score, reasons)

    bundle.risk_score = round(min(score, 1.0), 3)
    bundle.risk_level = _level(bundle.risk_score)
    bundle.detection_reasons = reasons
    return bundle


# ---------------------------------------------------------------------------
# Sub-scorers
# ---------------------------------------------------------------------------

def _score_consumer(
    consumer: EventConsumer | None, score: float, reasons: list[RiskDetail]
) -> tuple[float, list[RiskDetail]]:

    if consumer is None:
        reasons.append(RiskDetail("missing_consumer", 0.1,
            "Consumer not found — binding may be orphaned or partially deleted"))
        return score + 0.1, reasons

    if isinstance(consumer, ActiveScriptEventConsumer):
        reasons.append(RiskDetail("active_script_consumer", 0.5,
            "Executes arbitrary VBScript/JScript — highest-risk consumer type"))
        score += 0.5
        txt = consumer.script_text
        if txt and _BASE64_BLOCK.search(txt):
            reasons.append(RiskDetail("base64_in_script", 0.2, "Script contains a large Base64 block"))
            score += 0.2
        if txt and _DOWNLOAD.search(txt):
            reasons.append(RiskDetail("download_in_script", 0.15, "Script contains network/download indicators"))
            score += 0.15

    elif isinstance(consumer, CommandLineEventConsumer):
        reasons.append(RiskDetail("command_line_consumer", 0.3,
            "Executes an arbitrary command line — high-risk consumer type"))
        score += 0.3
        cmd = consumer.command_line_template or consumer.executable_path
        if cmd:
            if m := _LOLBINS.search(cmd):
                reasons.append(RiskDetail("lolbin_in_command", 0.2,
                    f"Command references '{m.group()}' — living-off-the-land binary"))
                score += 0.2
            if _DOWNLOAD.search(cmd):
                reasons.append(RiskDetail("download_in_command", 0.2, "Command contains network/download indicators"))
                score += 0.2
            if _FROMBASE64.search(cmd) or _BASE64_BLOCK.search(cmd):
                reasons.append(RiskDetail("base64_in_command", 0.2, "Command contains Base64 or -EncodedCommand"))
                score += 0.2
            if _TEMP_PATHS.search(cmd):
                reasons.append(RiskDetail("suspicious_path_in_command", 0.1,
                    "Command references a commonly abused writable path"))
                score += 0.1

    elif isinstance(consumer, SMTPEventConsumer):
        reasons.append(RiskDetail("smtp_consumer", 0.25,
            "May be used for data exfiltration or C2 notification via email"))
        score += 0.25

    elif isinstance(consumer, (NTEventLogEventConsumer, LogFileEventConsumer)):
        label = "ntevtlog_consumer" if isinstance(consumer, NTEventLogEventConsumer) else "logfile_consumer"
        reasons.append(RiskDetail(label, 0.05, f"{consumer.consumer_type} — low inherent risk"))
        score += 0.05

    else:
        reasons.append(RiskDetail("unknown_consumer_type", 0.15,
            f"'{consumer.consumer_type}' is not a standard WMI consumer class"))
        score += 0.15

    return score, reasons


def _score_filter(
    event_filter: EventFilter | None, score: float, reasons: list[RiskDetail]
) -> tuple[float, list[RiskDetail]]:

    if event_filter is None:
        reasons.append(RiskDetail("missing_filter", 0.1,
            "EventFilter not found — binding may be orphaned or partially deleted"))
        return score + 0.1, reasons

    if not event_filter.query:
        reasons.append(RiskDetail("no_query_extracted", 0.05,
            "WQL query could not be extracted — analysis completeness is reduced"))
        return score + 0.05, reasons

    if event_filter.is_broad_query():
        reasons.append(RiskDetail("broad_query", 0.1,
            f"Query has no WHERE clause — unusual for legitimate software: {event_filter.query[:80]}"))
        score += 0.1

    if m := _TIMER_RE.search(event_filter.query):
        ms = int(m.group(1))
        if ms < 60_000:
            reasons.append(RiskDetail("short_timer_interval", 0.1,
                f"Timer interval {ms} ms (<60 s) — reduces analyst reaction time"))
            score += 0.1

    return score, reasons


def _score_structural(
    bundle: WMIPersistenceBundle, score: float, reasons: list[RiskDetail]
) -> tuple[float, list[RiskDetail]]:

    ns = (
        (bundle.binding.namespace if bundle.binding else "")
        or (bundle.event_filter.namespace if bundle.event_filter else "")
    )

    if ns and not _STANDARD_NS.match(ns):
        reasons.append(RiskDetail("non_standard_namespace", 0.15,
            f"Namespace '{ns}' is not root\\\\subscription — used to evade detection tools"))
        score += 0.15
    elif not ns:
        reasons.append(RiskDetail("unknown_namespace", 0.05, "Namespace could not be determined"))
        score += 0.05

    if bundle.binding and bundle.binding.recovered_state in (
        RecoveredState.DELETED_RECOVERED, RecoveredState.CARVED
    ):
        label = "free page" if bundle.binding.recovered_state == RecoveredState.DELETED_RECOVERED else "carved region"
        reasons.append(RiskDetail("artefact_from_deleted_region", 0.1,
            f"Binding recovered from a {label} — past compromise or attacker cleanup"))
        score += 0.1

    if bundle.is_orphaned:
        reasons.append(RiskDetail("orphaned_binding", 0.1,
            "Filter or consumer not found — partial deletion or cross-namespace reference"))
        score += 0.1

    return score, reasons


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_known_legitimate(bundle: WMIPersistenceBundle) -> bool:
    if bundle.binding is None:
        return False
    key = (bundle.binding.consumer_name.lower().strip(), bundle.binding.filter_name.lower().strip())
    if note := _KNOWN_LEGITIMATE.get(key):
        bundle.legitimacy_note = note
        return True
    return False


def _level(score: float) -> str:
    if score < 0.3:
        return "low"
    if score < 0.6:
        return "medium"
    if score < 0.8:
        return "high"
    return "critical"
