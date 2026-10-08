"""Metadata-only security decision logging and in-process monitoring."""

import logging
from collections import Counter, deque
from datetime import datetime, timezone
from threading import Lock
from typing import Literal
from uuid import UUID

from pydantic import BaseModel

logger = logging.getLogger(__name__)

AuditEvent = Literal["analyze", "check_tool", "check_data", "check_action"]
SafeCategory = Literal["not_assessed", "unknown"]
SafeSeverity = Literal["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
DecisionAction = Literal["ALLOW", "BLOCK", "REVIEW"]
EventStatus = Literal["allowed", "review", "blocked"]


class MonitoringEvent(BaseModel):
    """An allow-listed record that cannot contain request content or secrets."""

    request_id: UUID | None
    event_type: AuditEvent
    timestamp: datetime
    source_type: Literal["file", "email", "web", "api", "database", "text"] | None
    threat_category: SafeCategory
    severity: SafeSeverity
    risk_score: int | None
    recommended_action: DecisionAction
    policy_decision: DecisionAction | None
    tool_decision: DecisionAction | None
    status: EventStatus


class AuditLogger:
    """Record bounded, safe metadata for monitoring and write safe log lines."""

    def __init__(self, max_events: int = 1000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be positive")
        self._events: deque[MonitoringEvent] = deque(maxlen=max_events)
        self._lock = Lock()

    def record(
        self,
        event: AuditEvent,
        decision: str,
        allowed: bool | None,
        request_id: UUID | None = None,
        *,
        source_type: str | None = None,
        threat_category: str | None = None,
        severity: str | None = None,
        risk_score: int | None = None,
        policy_decision: str | None = None,
        tool_decision: str | None = None,
    ) -> None:
        """Store only fixed vocabularies and validated numeric/identifier fields."""
        source_types = {"file", "email", "web", "api", "database", "text"}
        safe_source = (
            source_type
            if isinstance(source_type, str) and source_type in source_types
            else None
        )
        safe_category: SafeCategory = (
            threat_category if threat_category == "not_assessed" else "unknown"
        )
        safe_severity: SafeSeverity = (
            severity
            if isinstance(severity, str)
            and severity in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
            else "UNKNOWN"
        )
        safe_action: DecisionAction = (
            decision
            if isinstance(decision, str) and decision in {"ALLOW", "BLOCK", "REVIEW"}
            else "REVIEW"
        )
        safe_policy: DecisionAction | None = (
            policy_decision
            if isinstance(policy_decision, str)
            and policy_decision in {"ALLOW", "BLOCK", "REVIEW"}
            else None
        )
        safe_tool: DecisionAction | None = (
            tool_decision
            if isinstance(tool_decision, str)
            and tool_decision in {"ALLOW", "BLOCK", "REVIEW"}
            else None
        )
        safe_score = (
            risk_score
            if isinstance(risk_score, int)
            and not isinstance(risk_score, bool)
            and 0 <= risk_score <= 100
            else None
        )
        safe_allowed = allowed if isinstance(allowed, bool) else None
        status: EventStatus = (
            "allowed"
            if safe_allowed is True
            else "blocked"
            if safe_allowed is False
            else "review"
        )
        record = MonitoringEvent(
            request_id=request_id,
            event_type=event,
            timestamp=datetime.now(timezone.utc),
            source_type=safe_source,
            threat_category=safe_category,
            severity=safe_severity,
            risk_score=safe_score,
            recommended_action=safe_action,
            policy_decision=safe_policy,
            tool_decision=safe_tool,
            status=status,
        )
        with self._lock:
            self._events.append(record)
        logger.info(
            "security_audit event=%s request_id=%s decision=%s allowed=%s",
            event,
            request_id or "-",
            safe_action,
            safe_allowed,
        )

    def events(self, limit: int = 100) -> list[MonitoringEvent]:
        """Return newest safe event records first."""
        with self._lock:
            return list(reversed(list(self._events)[-limit:]))

    def summary(self) -> dict[str, object]:
        """Aggregate recorded events only; empty counters are safe zero values."""
        with self._lock:
            records = list(self._events)
        return {
            "total_events": len(records),
            "allowed_events": sum(record.status == "allowed" for record in records),
            "review_events": sum(record.status == "review" for record in records),
            "blocked_events": sum(record.status == "blocked" for record in records),
            "threat_categories": dict(Counter(record.threat_category for record in records)),
            "severities": dict(Counter(record.severity for record in records)),
            "policy_decisions": dict(
                Counter(
                    record.policy_decision
                    for record in records
                    if record.policy_decision
                )
            ),
            "source_types": dict(
                Counter(record.source_type for record in records if record.source_type)
            ),
        }
