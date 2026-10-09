"""Synthetic tests for deterministic, review-only incident analysis."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from backend.monitor.audit_logger import AuditLogger, MonitoringEvent
from backend.monitor.incident_analyzer import IncidentAnalyzer
from backend.monitor.incident_models import IncidentAnalyzerConfig

UTC = timezone.utc
T0 = datetime(2026, 1, 1, tzinfo=UTC)


def make_event(
    event_type: str = "check_tool",
    *,
    timestamp: datetime = T0,
    status: str = "blocked",
    severity: str = "UNKNOWN",
    risk_score: int | None = None,
    recommended_action: str = "BLOCK",
    tool_decision: str | None = "BLOCK",
    request_id=None,
) -> MonitoringEvent:
    return MonitoringEvent(
        request_id=request_id,
        event_type=event_type,
        timestamp=timestamp,
        source_type=None,
        threat_category="unknown",
        severity=severity,
        risk_score=risk_score,
        recommended_action=recommended_action,
        policy_decision=None,
        tool_decision=tool_decision,
        status=status,
    )


def test_empty_input_returns_complete_empty_report() -> None:
    report = IncidentAnalyzer().analyze([])

    assert report.analysis_status == "complete"
    assert report.events_received == 0
    assert report.events_in_window == 0
    assert report.reference_time is None
    assert report.findings == ()
    assert report.finding_count == 0
    assert report.error_code is None


def test_repeated_blocked_tool_checks_produce_review_finding() -> None:
    report = IncidentAnalyzer().analyze(
        [
            make_event(timestamp=T0),
            make_event(timestamp=T0 + timedelta(seconds=30)),
        ]
    )

    finding = report.findings[0]
    assert finding.rule_id == "repeated_blocked_tool_checks"
    assert finding.category == "suspicious_pattern"
    assert finding.review_required is True
    assert finding.matched_event_count == 2
    assert finding.event_types == ("check_tool",)
    assert "identities are unavailable" in finding.explanation


def test_single_blocked_tool_check_does_not_trigger_repetition() -> None:
    report = IncidentAnalyzer().analyze([make_event()])

    assert report.findings == ()


def test_repeated_blocked_data_checks_use_generic_review_label() -> None:
    report = IncidentAnalyzer().analyze(
        [
            make_event("check_data", timestamp=T0, tool_decision=None),
            make_event(
                "check_data",
                timestamp=T0 + timedelta(seconds=5),
                tool_decision=None,
                recommended_action="BLOCK",
            ),
        ]
    )

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.rule_id == "repeated_blocked_data_checks"
    assert finding.event_types == ("check_data",)
    assert "data classification and destination are unavailable" in finding.explanation
    assert "exfiltration" not in finding.rule_id
    assert "exfiltration" not in finding.explanation


def test_high_risk_burst_counts_overlapping_score_and_severity_once() -> None:
    report = IncidentAnalyzer().analyze(
        [
            make_event(
                "analyze",
                timestamp=T0,
                status="review",
                severity="HIGH",
                risk_score=85,
                recommended_action="REVIEW",
                tool_decision=None,
            ),
            make_event(
                "analyze",
                timestamp=T0 + timedelta(seconds=10),
                status="allowed",
                severity="LOW",
                risk_score=80,
                recommended_action="ALLOW",
                tool_decision=None,
            ),
        ]
    )

    finding = report.findings[0]
    assert finding.rule_id == "high_risk_analysis_burst"
    assert finding.matched_event_count == 2
    assert finding.evidence.score_qualified_event_count == 2
    assert finding.evidence.high_severity_event_count == 1
    assert finding.evidence.risk_score_threshold == 70


def test_events_outside_reference_window_do_not_combine() -> None:
    latest = T0 + timedelta(minutes=10)
    report = IncidentAnalyzer(
        IncidentAnalyzerConfig(analysis_window_seconds=300)
    ).analyze(
        [make_event(timestamp=T0), make_event(timestamp=latest)],
        reference_time=latest,
    )

    assert report.events_received == 2
    assert report.events_in_window == 1
    assert report.findings == ()


def test_missing_scores_and_unknown_severity_are_not_risk_evidence() -> None:
    events = [
        make_event(
            "analyze",
            timestamp=T0,
            status="review",
            severity="UNKNOWN",
            risk_score=None,
            recommended_action="REVIEW",
            tool_decision=None,
        ),
        make_event(
            "analyze",
            timestamp=T0 + timedelta(seconds=1),
            status="review",
            severity="UNKNOWN",
            risk_score=None,
            recommended_action="REVIEW",
            tool_decision=None,
        ),
    ]

    assert IncidentAnalyzer().analyze(events).findings == ()


def test_invalid_configuration_is_rejected() -> None:
    with pytest.raises(ValidationError):
        IncidentAnalyzerConfig(analysis_window_seconds=0)
    with pytest.raises(ValidationError):
        IncidentAnalyzerConfig(minimum_pattern_events=1)
    with pytest.raises(ValidationError):
        IncidentAnalyzerConfig(max_events=1)
    with pytest.raises(ValidationError):
        IncidentAnalyzerConfig(max_events=2, high_risk_minimum_events=3)


def test_malformed_event_and_timestamp_fail_without_leaking_details() -> None:
    secret = "malformed-event-secret-token"
    analyzer = IncidentAnalyzer()
    malformed_mapping = {
        "event_type": "check_tool",
        "raw_prompt": secret,
        "content": secret,
        "password": secret,
        "api_key": secret,
        "access_token": secret,
        "tool_arguments": {"token": secret},
        "arguments": {"credential": secret},
        "indicators": [secret],
        "reasons": [secret],
        "request_id": secret,
        "reason": secret,
    }
    malformed_timestamp = make_event().model_copy(
        update={"timestamp": f"{secret} invalid timestamp"}
    )

    for bad_events in ([malformed_mapping], [malformed_timestamp]):
        report = analyzer.analyze(bad_events)  # type: ignore[arg-type]
        serialized = report.model_dump_json()
        assert report.analysis_status == "invalid_input"
        assert report.error_code == "invalid_input"
        assert report.findings == ()
        assert secret not in serialized
        assert "reason" not in serialized
        assert "tool_arguments" not in serialized
        assert "raw_prompt" not in serialized
        assert "password" not in serialized
        assert "api_key" not in serialized
        assert "access_token" not in serialized
        assert "indicators" not in serialized
        assert "request_id" not in serialized


def test_naive_event_and_reference_timestamps_fail_safely() -> None:
    analyzer = IncidentAnalyzer()
    naive_event = make_event().model_copy(
        update={"timestamp": datetime(2026, 1, 1)}
    )

    event_report = analyzer.analyze([naive_event])
    reference_report = analyzer.analyze(
        [make_event()], reference_time=datetime(2026, 1, 1)
    )

    assert event_report.analysis_status == "invalid_input"
    assert reference_report.analysis_status == "invalid_input"
    assert event_report.findings == reference_report.findings == ()


def test_missing_score_does_not_hide_high_severity_evidence() -> None:
    events = [
        make_event(
            "analyze",
            timestamp=T0,
            severity="HIGH",
            risk_score=None,
            status="review",
            recommended_action="REVIEW",
            tool_decision=None,
        ),
        make_event(
            "analyze",
            timestamp=T0 + timedelta(seconds=1),
            severity="CRITICAL",
            risk_score=None,
            status="review",
            recommended_action="REVIEW",
            tool_decision=None,
        ),
    ]

    finding = IncidentAnalyzer().analyze(events).findings[0]

    assert finding.rule_id == "high_risk_analysis_burst"
    assert finding.matched_event_count == 2
    assert finding.evidence.score_qualified_event_count == 0
    assert finding.evidence.high_severity_event_count == 2


def test_analyzer_invokes_no_network_or_subprocess_calls(monkeypatch) -> None:
    import socket
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("external operation attempted")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    report = IncidentAnalyzer().analyze(
        [make_event(timestamp=T0), make_event(timestamp=T0 + timedelta(seconds=1))]
    )

    assert report.analysis_status == "complete"
    assert report.findings[0].review_required is True


def test_event_limit_returns_fixed_report_without_partial_findings() -> None:
    config = IncidentAnalyzerConfig(max_events=2)
    analyzer = IncidentAnalyzer(config)
    consumed: list[int] = []

    def event_stream():
        number = 0
        while True:
            consumed.append(number)
            yield make_event(timestamp=T0 + timedelta(seconds=number))
            number += 1

    report = analyzer.analyze(event_stream())

    assert report.analysis_status == "limit_exceeded"
    assert report.error_code == "event_limit_exceeded"
    assert report.events_received == 0
    assert report.events_in_window == 0
    assert report.reference_time is None
    assert report.findings == ()
    assert consumed == [0, 1, 2]


def test_equal_timestamps_are_unordered_and_results_are_deterministic() -> None:
    events = [
        make_event("check_data", timestamp=T0, tool_decision=None),
        make_event("check_tool", timestamp=T0),
        make_event("check_data", timestamp=T0, tool_decision=None),
        make_event("check_tool", timestamp=T0),
    ]
    analyzer = IncidentAnalyzer()

    forward = analyzer.analyze(events)
    reverse = analyzer.analyze(list(reversed(events)))

    assert forward.model_dump(mode="json") == reverse.model_dump(mode="json")
    assert [finding.rule_id for finding in forward.findings] == [
        "repeated_blocked_tool_checks",
        "repeated_blocked_data_checks",
    ]
    assert all(finding.first_seen == finding.last_seen == T0 for finding in forward.findings)


def test_identical_input_and_configuration_produce_identical_reports() -> None:
    config = IncidentAnalyzerConfig(analysis_window_seconds=60)
    events = [
        make_event(timestamp=T0),
        make_event(timestamp=T0 + timedelta(seconds=10)),
    ]

    first = IncidentAnalyzer(config).analyze(events)
    second = IncidentAnalyzer(config).analyze(events)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_report_excludes_request_ids_and_untrusted_payload_fields() -> None:
    request_id = uuid4()
    events = [
        make_event(timestamp=T0, request_id=request_id),
        make_event(timestamp=T0 + timedelta(seconds=1), request_id=request_id),
    ]
    report = IncidentAnalyzer().analyze(events)
    serialized = report.model_dump_json()

    assert str(request_id) not in serialized
    assert "request_id" not in serialized
    assert "raw_prompt" not in serialized
    assert "tool_arguments" not in serialized
    assert "indicators" not in serialized
    assert "reason" not in serialized
    assert "recommended_action" not in serialized
    assert "allowed" not in serialized


def test_duplicate_events_are_counted_as_distinct_records() -> None:
    duplicate = make_event(timestamp=T0)
    report = IncidentAnalyzer().analyze([duplicate, duplicate])

    assert len(report.findings) == 1
    assert report.findings[0].matched_event_count == 2


def test_max_findings_truncation_is_stable_and_reported() -> None:
    config = IncidentAnalyzerConfig(max_findings=1)
    events = [
        make_event("check_tool", timestamp=T0),
        make_event("check_tool", timestamp=T0 + timedelta(seconds=1)),
        make_event("check_data", timestamp=T0, tool_decision=None),
        make_event(
            "check_data",
            timestamp=T0 + timedelta(seconds=1),
            tool_decision=None,
        ),
    ]

    report = IncidentAnalyzer(config).analyze(events)

    assert report.finding_count == 1
    assert report.total_findings == 2
    assert report.findings_truncated is True
    assert report.findings[0].rule_id == "repeated_blocked_tool_checks"


def test_analysis_does_not_mutate_events_or_audit_logger_state() -> None:
    logger = AuditLogger()
    logger.record(
        "check_tool",
        "BLOCK",
        False,
        tool_decision="BLOCK",
    )
    before = [item.model_dump(mode="json") for item in logger.events()]
    snapshot = logger.events()
    snapshot_before = [item.model_dump(mode="json") for item in snapshot]

    report = IncidentAnalyzer().analyze(snapshot)

    assert report.findings == ()
    assert [item.model_dump(mode="json") for item in snapshot] == snapshot_before
    assert [item.model_dump(mode="json") for item in logger.events()] == before


def test_findings_are_review_only_and_never_claim_unsupported_rules() -> None:
    report = IncidentAnalyzer().analyze(
        [
            make_event(timestamp=T0),
            make_event(timestamp=T0 + timedelta(seconds=1)),
        ]
    )

    assert {finding.rule_id for finding in report.findings} <= {
        "repeated_blocked_tool_checks",
        "repeated_blocked_data_checks",
        "high_risk_analysis_burst",
    }
    for finding in report.findings:
        assert finding.category == "suspicious_pattern"
        assert finding.review_required is True
        assert not hasattr(finding, "action")
        assert not hasattr(finding, "allowed")


def test_config_rejects_coercible_non_integer_bounds() -> None:
    for invalid_value in ("10", 10.0, True):
        with pytest.raises(ValidationError):
            IncidentAnalyzerConfig(max_events=invalid_value)


def test_invalid_enum_and_boolean_score_fail_closed_without_reflection() -> None:
    secret = "unexpected-enum-secret"
    invalid_events = [
        make_event().model_copy(update={"event_type": secret}),
        make_event("analyze").model_copy(update={"risk_score": True}),
    ]

    for event in invalid_events:
        report = IncidentAnalyzer().analyze([event])
        serialized = report.model_dump_json()
        assert report.analysis_status == "invalid_input"
        assert report.error_code == "invalid_input"
        assert report.findings == ()
        assert secret not in serialized


def test_window_boundaries_are_inclusive_across_timezone_offsets() -> None:
    offset = timezone(timedelta(hours=5, minutes=30))
    reference = datetime(2026, 1, 1, 5, 31, tzinfo=offset)
    at_start = datetime(2026, 1, 1, 5, 30, tzinfo=offset)
    just_before_start = T0 - timedelta(microseconds=1)

    report = IncidentAnalyzer(
        IncidentAnalyzerConfig(analysis_window_seconds=60)
    ).analyze(
        [
            make_event(timestamp=at_start),
            make_event(timestamp=reference),
            make_event(timestamp=just_before_start),
        ],
        reference_time=reference,
    )

    assert report.reference_time == T0 + timedelta(minutes=1)
    assert report.events_received == 3
    assert report.events_in_window == 2
    finding = report.findings[0]
    assert finding.matched_event_count == 2
    assert finding.first_seen == T0
    assert finding.last_seen == T0 + timedelta(minutes=1)


def test_high_risk_score_threshold_is_inclusive() -> None:
    events = [
        make_event(
            "analyze",
            timestamp=T0 + timedelta(seconds=index),
            status="review",
            severity="LOW",
            risk_score=score,
            recommended_action="REVIEW",
            tool_decision=None,
        )
        for index, score in enumerate((70, 69, 70))
    ]

    finding = IncidentAnalyzer().analyze(events).findings[0]

    assert finding.rule_id == "high_risk_analysis_burst"
    assert finding.matched_event_count == 2
    assert finding.evidence.score_qualified_event_count == 2
    assert finding.evidence.high_severity_event_count == 0


def test_blocked_pattern_rules_require_all_documented_metadata_gates() -> None:
    events = [
        make_event("check_tool", status="blocked", tool_decision=None),
        make_event("check_tool", status="review", tool_decision="BLOCK"),
        make_event("check_tool", status="blocked", tool_decision="ALLOW"),
        make_event(
            "check_data",
            status="blocked",
            recommended_action="REVIEW",
            tool_decision=None,
        ),
        make_event(
            "check_data",
            status="review",
            recommended_action="BLOCK",
            tool_decision=None,
        ),
    ]

    assert IncidentAnalyzer().analyze(events).findings == ()


def test_iterator_exception_returns_fixed_failure_without_partial_findings() -> None:
    secret = "iterator-exception-secret"

    def broken_stream():
        yield make_event(timestamp=T0)
        yield make_event(timestamp=T0 + timedelta(seconds=1))
        raise RuntimeError(secret)

    report = IncidentAnalyzer().analyze(broken_stream())
    serialized = report.model_dump_json()

    assert report.analysis_status == "invalid_input"
    assert report.error_code == "invalid_input"
    assert report.events_received == 0
    assert report.findings == ()
    assert secret not in serialized


def test_nested_report_serialization_has_only_allowlisted_fields() -> None:
    report = IncidentAnalyzer().analyze(
        [
            make_event(timestamp=T0),
            make_event(timestamp=T0 + timedelta(seconds=1)),
        ]
    )
    data = report.model_dump(mode="json")

    assert set(data) == {
        "analysis_status",
        "events_received",
        "events_in_window",
        "reference_time",
        "findings",
        "finding_count",
        "total_findings",
        "findings_truncated",
        "error_code",
    }
    finding = data["findings"][0]
    assert set(finding) == {
        "rule_id",
        "category",
        "review_required",
        "matched_event_count",
        "first_seen",
        "last_seen",
        "event_types",
        "evidence",
        "explanation",
    }
    assert set(finding["evidence"]) == {
        "required_event_count",
        "window_seconds",
        "risk_score_threshold",
        "score_qualified_event_count",
        "high_severity_event_count",
    }
    serialized = report.model_dump_json()
    for prohibited in (
        "request_id",
        "raw_prompt",
        "password",
        "api_key",
        "access_token",
        "tool_arguments",
        "indicators",
        "reason",
        "source_type",
        "threat_category",
        "recommended_action",
        "policy_decision",
        "tool_decision",
        "status",
    ):
        assert f'"{prohibited}":' not in serialized
