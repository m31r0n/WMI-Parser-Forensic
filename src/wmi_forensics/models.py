"""Core data models for WMI forensic artefacts."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RecoveredState(str, Enum):
    ACTIVE = "active"
    DELETED_RECOVERED = "deleted_recovered"
    CARVED = "carved"
    UNKNOWN = "unknown"


class DataEncoding(str, Enum):
    UTF16LE = "utf-16-le"
    ASCII = "ascii"
    MIXED = "mixed"
    UNKNOWN = "unknown"


@dataclass
class ParseWarning:
    field_name: str
    message: str
    severity: str = "warn"


@dataclass
class RiskDetail:
    factor: str
    contribution: float
    explanation: str


@dataclass
class EventFilter:
    name: str
    query: str = ""
    query_language: str = "WQL"
    namespace: str = ""
    creator_sid: str = ""
    offset: int = -1
    length: int = -1
    file_path: str = ""
    encoding: DataEncoding = DataEncoding.UNKNOWN
    recovered_state: RecoveredState = RecoveredState.UNKNOWN
    confidence: float = 1.0
    raw_preview: bytes = field(default_factory=bytes)
    parse_warnings: list[ParseWarning] = field(default_factory=list)

    def is_broad_query(self) -> bool:
        """True when the WQL query has no WHERE clause (triggers on all matching events)."""
        q = self.query.strip().upper()
        return bool(q.startswith("SELECT") and "WHERE" not in q and q != "")


@dataclass
class EventConsumer:
    name: str
    consumer_type: str
    namespace: str = ""
    creator_sid: str = ""
    offset: int = -1
    length: int = -1
    file_path: str = ""
    encoding: DataEncoding = DataEncoding.UNKNOWN
    recovered_state: RecoveredState = RecoveredState.UNKNOWN
    confidence: float = 1.0
    raw_preview: bytes = field(default_factory=bytes)
    parse_warnings: list[ParseWarning] = field(default_factory=list)


@dataclass
class CommandLineEventConsumer(EventConsumer):
    command_line_template: str = ""
    executable_path: str = ""
    working_directory: str = ""
    run_interactive_session: bool | None = None
    show_window_command: int | None = None

    def __post_init__(self) -> None:
        self.consumer_type = "CommandLineEventConsumer"


@dataclass
class ActiveScriptEventConsumer(EventConsumer):
    script_text: str = ""
    script_filename: str = ""
    scripting_engine: str = ""
    kill_timeout: int | None = None

    def __post_init__(self) -> None:
        self.consumer_type = "ActiveScriptEventConsumer"


@dataclass
class NTEventLogEventConsumer(EventConsumer):
    source_name: str = ""
    event_id: int | None = None
    event_type: int | None = None
    category: int | None = None
    insertion_strings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.consumer_type = "NTEventLogEventConsumer"


@dataclass
class LogFileEventConsumer(EventConsumer):
    filename: str = ""
    text: str = ""
    max_file_size: int | None = None
    is_unicode: bool | None = None

    def __post_init__(self) -> None:
        self.consumer_type = "LogFileEventConsumer"


@dataclass
class SMTPEventConsumer(EventConsumer):
    smtp_server: str = ""
    to_line: str = ""
    cc_line: str = ""
    bcc_line: str = ""
    reply_to_line: str = ""
    subject: str = ""
    message: str = ""
    from_line: str = ""

    def __post_init__(self) -> None:
        self.consumer_type = "SMTPEventConsumer"


@dataclass
class GenericEventConsumer(EventConsumer):
    raw_properties: dict[str, str] = field(default_factory=dict)


@dataclass
class FilterToConsumerBinding:
    consumer_name: str
    consumer_type: str
    filter_name: str
    namespace: str = ""
    offset: int = -1
    length: int = -1
    file_path: str = ""
    encoding: DataEncoding = DataEncoding.UNKNOWN
    recovered_state: RecoveredState = RecoveredState.UNKNOWN
    confidence: float = 1.0
    raw_preview: bytes = field(default_factory=bytes)
    parse_warnings: list[ParseWarning] = field(default_factory=list)


@dataclass
class WMIPersistenceBundle:
    """
    Correlated persistence artefact: one binding with its resolved filter and consumer.

    risk_score ranges 0.0–1.0:
        0.0–0.29  low      likely legitimate
        0.3–0.59  medium   warrants manual review
        0.6–0.79  high     unusual; probable offensive use
        0.8–1.0   critical strong structural indicators

    Every score contribution is recorded in detection_reasons.
    This is a triage score, not a verdict.
    """
    artifact_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    binding: FilterToConsumerBinding | None = None
    event_filter: EventFilter | None = None
    consumer: EventConsumer | None = None
    is_orphaned: bool = False
    is_incomplete: bool = False
    is_known_legitimate: bool = False
    legitimacy_note: str = ""
    risk_score: float = 0.0
    risk_level: str = "unknown"
    detection_reasons: list[RiskDetail] = field(default_factory=list)
    orphaned_filter: EventFilter | None = None
    orphaned_consumer: EventConsumer | None = None

    def display_name(self) -> str:
        consumer_name = (
            self.consumer.name if self.consumer
            else (self.binding.consumer_name if self.binding else "?")
        )
        filter_name = (
            self.event_filter.name if self.event_filter
            else (self.binding.filter_name if self.binding else "?")
        )
        return f"{consumer_name} -> {filter_name}"


def bundle_to_dict(bundle: WMIPersistenceBundle) -> dict[str, Any]:
    """Convert a WMIPersistenceBundle to a JSON-serialisable dictionary."""
    import dataclasses

    def walk(obj: Any) -> Any:
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return {k: walk(v) for k, v in dataclasses.asdict(obj).items()}
        if isinstance(obj, bytes):
            return obj.hex()
        if hasattr(obj, "value"):
            return obj.value
        if isinstance(obj, list):
            return [walk(i) for i in obj]
        if isinstance(obj, dict):
            return {k: walk(v) for k, v in obj.items()}
        return obj

    return walk(bundle)
