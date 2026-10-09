"""Typed, metadata-only models for reviewable incident patterns."""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.monitor.audit_logger import AuditEvent

IncidentRuleId = Literal[
    "repeated_blocked_tool_checks",
    "repeated_blocked_data_checks",
    "high_risk_analysis_burst",
]
FindingExplanation = Literal[
    "Multiple blocked tool checks occurred within the configured window; tool and agent identities are unavailable.",
    "Multiple blocked data checks occurred within the configured window; data classification and destination are unavailable.",
    "Multiple high-risk analyses occurred within the configured window; this pattern is not proof of an attack.",
]
AnalysisStatus = Literal["complete", "invalid_input", "limit_exceeded"]
AnalysisErrorCode = Literal["invalid_input", "event_limit_exceeded"]


class IncidentAnalyzerConfig(BaseModel):
    """Validated resource and rule bounds for one deterministic analysis."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    max_events: int = Field(default=1000, ge=2, le=10_000)
    analysis_window_seconds: int = Field(default=300, ge=1, le=86_400)
    minimum_pattern_events: int = Field(default=2, ge=2, le=10_000)
    high_risk_minimum_events: int = Field(default=2, ge=2, le=10_000)
    high_risk_score_threshold: int = Field(default=70, ge=0, le=100)
    max_findings: int = Field(default=3, ge=1, le=3)

    @model_validator(mode="after")
    def thresholds_fit_event_limit(self) -> "IncidentAnalyzerConfig":
        if self.minimum_pattern_events > self.max_events:
            raise ValueError("minimum_pattern_events exceeds max_events")
        if self.high_risk_minimum_events > self.max_events:
            raise ValueError("high_risk_minimum_events exceeds max_events")
        return self


class IncidentEvidence(BaseModel):
    """Safe numeric evidence; never contains event content or identifiers."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    required_event_count: int = Field(ge=2, le=10_000)
    window_seconds: int = Field(ge=1, le=86_400)
    risk_score_threshold: int | None = Field(default=None, ge=0, le=100)
    score_qualified_event_count: int = Field(default=0, ge=0, le=10_000)
    high_severity_event_count: int = Field(default=0, ge=0, le=10_000)


class IncidentFinding(BaseModel):
    """A fixed-vocabulary, review-only summary of a repeated pattern."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: IncidentRuleId
    category: Literal["suspicious_pattern"] = "suspicious_pattern"
    review_required: Literal[True] = True
    matched_event_count: int = Field(ge=2, le=10_000)
    first_seen: datetime
    last_seen: datetime
    event_types: tuple[AuditEvent, ...]
    evidence: IncidentEvidence
    explanation: FindingExplanation

    @field_validator("first_seen", "last_seen")
    @classmethod
    def timestamps_are_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("finding timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def time_and_evidence_are_consistent(self) -> "IncidentFinding":
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen must not follow last_seen")
        if self.matched_event_count < self.evidence.required_event_count:
            raise ValueError("matched_event_count is below its threshold")
        return self


class IncidentAnalysisReport(BaseModel):
    """Complete result or a fixed safe failure with no partial findings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    analysis_status: AnalysisStatus
    events_received: int = Field(ge=0, le=10_000)
    events_in_window: int = Field(ge=0, le=10_000)
    reference_time: datetime | None = None
    findings: tuple[IncidentFinding, ...] = ()
    finding_count: int = Field(ge=0, le=3)
    total_findings: int = Field(ge=0, le=3)
    findings_truncated: bool = False
    error_code: AnalysisErrorCode | None = None

    @field_validator("reference_time")
    @classmethod
    def reference_time_is_aware_utc(
        cls, value: datetime | None
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("reference_time must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def report_counts_and_status_are_consistent(self) -> "IncidentAnalysisReport":
        if self.events_in_window > self.events_received:
            raise ValueError("events_in_window exceeds events_received")
        if self.finding_count != len(self.findings):
            raise ValueError("finding_count does not match findings")
        if self.total_findings < self.finding_count:
            raise ValueError("total_findings is below finding_count")
        if self.findings_truncated != (self.total_findings > self.finding_count):
            raise ValueError("findings_truncated does not match finding counts")

        if self.analysis_status == "complete":
            if self.error_code is not None:
                raise ValueError("complete report cannot have an error code")
            return self

        expected_error: AnalysisErrorCode = (
            "invalid_input"
            if self.analysis_status == "invalid_input"
            else "event_limit_exceeded"
        )
        if (
            self.error_code != expected_error
            or self.events_received != 0
            or self.events_in_window != 0
            or self.reference_time is not None
            or self.findings
            or self.finding_count != 0
            or self.total_findings != 0
            or self.findings_truncated
        ):
            raise ValueError("failed reports must not contain partial analysis")
        return self
