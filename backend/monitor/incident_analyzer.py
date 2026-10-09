"""Pure analysis of sanitized monitoring-event snapshots."""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from backend.monitor.audit_logger import (
    AuditEvent,
    DecisionAction,
    EventStatus,
    MonitoringEvent,
    SafeSeverity,
)
from backend.monitor.incident_models import (
    AnalysisErrorCode,
    FindingExplanation,
    IncidentRuleId,
    IncidentAnalysisReport,
    IncidentAnalyzerConfig,
    IncidentEvidence,
    IncidentFinding,
)


@dataclass(frozen=True, slots=True)
class _SafeEvent:
    """Minimal event fields needed by the supported rules."""

    timestamp: datetime
    event_type: AuditEvent
    status: EventStatus
    severity: SafeSeverity
    risk_score: int | None
    recommended_action: DecisionAction
    tool_decision: DecisionAction | None


class IncidentAnalyzer:
    """Return deterministic review findings from an already-sanitized snapshot.

    The analysis window is inclusive: [reference_time - window, reference_time].
    If no reference time is supplied, the latest event timestamp is used. No wall
    clock, logger state, persistence, enforcement, or external service is used.
    """

    def __init__(self, config: IncidentAnalyzerConfig | None = None) -> None:
        if config is None:
            config = IncidentAnalyzerConfig()
        if type(config) is not IncidentAnalyzerConfig:
            raise TypeError("config must be an IncidentAnalyzerConfig")
        # Revalidate even model_construct-created instances without retaining
        # mutable state supplied by the caller.
        self._config = IncidentAnalyzerConfig.model_validate(config.model_dump())

    def analyze(
        self,
        events: Iterable[MonitoringEvent],
        *,
        reference_time: datetime | None = None,
    ) -> IncidentAnalysisReport:
        """Analyze a bounded snapshot; failures return fixed reports without data."""
        normalized_reference: datetime | None = None
        if reference_time is not None:
            normalized_reference = self._as_utc(reference_time)
            if normalized_reference is None:
                return self._failure("invalid_input")

        safe_events, error = self._read_events(events)
        if error is not None:
            return self._failure(error)

        if normalized_reference is None and safe_events:
            normalized_reference = max(event.timestamp for event in safe_events)
        if normalized_reference is None:
            return self._complete_report(0, 0, None, ())

        try:
            window_start = normalized_reference - timedelta(
                seconds=self._config.analysis_window_seconds
            )
        except OverflowError:
            return self._failure("invalid_input")

        safe_events.sort(key=self._sort_key)
        in_window = [
            event
            for event in safe_events
            if window_start <= event.timestamp <= normalized_reference
        ]

        findings: list[IncidentFinding] = []

        blocked_tool_events = [
            event
            for event in in_window
            if (
                event.event_type == "check_tool"
                and event.tool_decision == "BLOCK"
                and event.status == "blocked"
            )
        ]
        if len(blocked_tool_events) >= self._config.minimum_pattern_events:
            findings.append(
                self._finding(
                    rule_id="repeated_blocked_tool_checks",
                    events=blocked_tool_events,
                    required_count=self._config.minimum_pattern_events,
                    event_type="check_tool",
                    explanation=(
                        "Multiple blocked tool checks occurred within the configured "
                        "window; tool and agent identities are unavailable."
                    ),
                )
            )

        blocked_data_events = [
            event
            for event in in_window
            if (
                event.event_type == "check_data"
                and event.recommended_action == "BLOCK"
                and event.status == "blocked"
            )
        ]
        if len(blocked_data_events) >= self._config.minimum_pattern_events:
            findings.append(
                self._finding(
                    rule_id="repeated_blocked_data_checks",
                    events=blocked_data_events,
                    required_count=self._config.minimum_pattern_events,
                    event_type="check_data",
                    explanation=(
                        "Multiple blocked data checks occurred within the configured "
                        "window; data classification and destination are unavailable."
                    ),
                )
            )

        high_risk_analyses = [
            event
            for event in in_window
            if (
                event.event_type == "analyze"
                and (
                    (
                        event.risk_score is not None
                        and event.risk_score
                        >= self._config.high_risk_score_threshold
                    )
                    or event.severity in {"HIGH", "CRITICAL"}
                )
            )
        ]
        if len(high_risk_analyses) >= self._config.high_risk_minimum_events:
            score_count = sum(
                event.risk_score is not None
                and event.risk_score >= self._config.high_risk_score_threshold
                for event in high_risk_analyses
            )
            severity_count = sum(
                event.severity in {"HIGH", "CRITICAL"}
                for event in high_risk_analyses
            )
            findings.append(
                self._finding(
                    rule_id="high_risk_analysis_burst",
                    events=high_risk_analyses,
                    required_count=self._config.high_risk_minimum_events,
                    event_type="analyze",
                    explanation=(
                        "Multiple high-risk analyses occurred within the configured "
                        "window; this pattern is not proof of an attack."
                    ),
                    risk_score_threshold=self._config.high_risk_score_threshold,
                    score_qualified_event_count=score_count,
                    high_severity_event_count=severity_count,
                )
            )

        total_findings = len(findings)
        returned_findings = tuple(findings[: self._config.max_findings])
        return self._complete_report(
            events_received=len(safe_events),
            events_in_window=len(in_window),
            reference_time=normalized_reference,
            findings=returned_findings,
            total_findings=total_findings,
        )

    def _read_events(
        self, events: Iterable[MonitoringEvent]
    ) -> tuple[list[_SafeEvent], AnalysisErrorCode | None]:
        try:
            iterator: Iterator[MonitoringEvent] = iter(events)
        except Exception:
            return [], "invalid_input"

        safe_events: list[_SafeEvent] = []
        for position in range(self._config.max_events + 1):
            try:
                event = next(iterator)
            except StopIteration:
                return safe_events, None
            except Exception:
                return [], "invalid_input"

            if position >= self._config.max_events:
                return [], "event_limit_exceeded"

            safe_event = self._normalize_event(event)
            if safe_event is None:
                return [], "invalid_input"
            safe_events.append(safe_event)
        return safe_events, None

    @staticmethod
    def _normalize_event(event: object) -> _SafeEvent | None:
        if type(event) is not MonitoringEvent:
            return None
        try:
            if not isinstance(event.timestamp, datetime):
                return None
            if event.risk_score is not None and type(event.risk_score) is not int:
                return None
            if event.risk_score is not None and not 0 <= event.risk_score <= 100:
                return None

            # Explicit reconstruction validates declared fields and drops any
            # possible extra attributes. The request ID is validated but never
            # copied into the internal representation or report.
            validated = MonitoringEvent(
                request_id=event.request_id,
                event_type=event.event_type,
                timestamp=event.timestamp,
                source_type=event.source_type,
                threat_category=event.threat_category,
                severity=event.severity,
                risk_score=event.risk_score,
                recommended_action=event.recommended_action,
                policy_decision=event.policy_decision,
                tool_decision=event.tool_decision,
                status=event.status,
            )
            timestamp = IncidentAnalyzer._as_utc(validated.timestamp)
            if timestamp is None:
                return None
            return _SafeEvent(
                timestamp=timestamp,
                event_type=validated.event_type,
                status=validated.status,
                severity=validated.severity,
                risk_score=validated.risk_score,
                recommended_action=validated.recommended_action,
                tool_decision=validated.tool_decision,
            )
        except Exception:
            # Never expose validation details or source representations.
            return None

    @staticmethod
    def _as_utc(value: object) -> datetime | None:
        if not isinstance(value, datetime):
            return None
        try:
            if value.tzinfo is None or value.utcoffset() is None:
                return None
            return value.astimezone(timezone.utc)
        except Exception:
            return None

    @staticmethod
    def _sort_key(event: _SafeEvent) -> tuple[object, ...]:
        # This ordering is only for stable aggregation. Equal timestamps do not
        # establish a causal sequence; no rule infers order from them.
        return (
            event.timestamp,
            event.event_type,
            event.status,
            event.recommended_action,
            event.tool_decision or "",
            event.severity,
            -1 if event.risk_score is None else event.risk_score,
        )

    def _finding(
        self,
        *,
        rule_id: IncidentRuleId,
        events: list[_SafeEvent],
        required_count: int,
        event_type: AuditEvent,
        explanation: FindingExplanation,
        risk_score_threshold: int | None = None,
        score_qualified_event_count: int = 0,
        high_severity_event_count: int = 0,
    ) -> IncidentFinding:
        timestamps = [event.timestamp for event in events]
        return IncidentFinding(
            rule_id=rule_id,
            matched_event_count=len(events),
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            event_types=(event_type,),
            evidence=IncidentEvidence(
                required_event_count=required_count,
                window_seconds=self._config.analysis_window_seconds,
                risk_score_threshold=risk_score_threshold,
                score_qualified_event_count=score_qualified_event_count,
                high_severity_event_count=high_severity_event_count,
            ),
            explanation=explanation,
        )

    @staticmethod
    def _failure(error: AnalysisErrorCode) -> IncidentAnalysisReport:
        return IncidentAnalysisReport(
            analysis_status=(
                "limit_exceeded"
                if error == "event_limit_exceeded"
                else "invalid_input"
            ),
            events_received=0,
            events_in_window=0,
            reference_time=None,
            findings=(),
            finding_count=0,
            total_findings=0,
            findings_truncated=False,
            error_code=error,
        )

    @staticmethod
    def _complete_report(
        events_received: int,
        events_in_window: int,
        reference_time: datetime | None,
        findings: tuple[IncidentFinding, ...],
        total_findings: int | None = None,
    ) -> IncidentAnalysisReport:
        total = len(findings) if total_findings is None else total_findings
        return IncidentAnalysisReport(
            analysis_status="complete",
            events_received=events_received,
            events_in_window=events_in_window,
            reference_time=reference_time,
            findings=findings,
            finding_count=len(findings),
            total_findings=total,
            findings_truncated=total > len(findings),
            error_code=None,
        )
