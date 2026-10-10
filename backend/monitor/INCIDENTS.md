# Incident analysis

## Purpose and scope

This module analyzes an already-sanitized snapshot of MonitoringEvent records and returns deterministic summaries of repeated patterns that may deserve human review. A finding is a suspicious pattern, not a confirmed attack. The analyzer is separate from detection, risk scoring, policy decisions, logging, and enforcement.

The analyzer is in-memory and read-only. It does not call external services, persist events, change logger state, or execute actions.

## Public interface

    from backend.monitor.incident_analyzer import IncidentAnalyzer
    from backend.monitor.incident_models import IncidentAnalyzerConfig

    analyzer = IncidentAnalyzer(IncidentAnalyzerConfig())
    events = security_service.audit_logger.events(limit=100)
    report = analyzer.analyze(events)

    for finding in report.findings:
        if finding.review_required:
            print(finding.rule_id, finding.matched_event_count)

SecurityService exposes its existing logger as security_service.audit_logger. AuditLogger.events(limit=100) returns a newest-first snapshot. The API route also returns MonitoringEvent records, with a query limit from 1 through 1,000. The analyzer sorts its own safe copy and never changes the input list, event objects, or logger state.

## Supported rules

| Rule ID | Required evidence | Meaning |
|---|---|---|
| repeated_blocked_tool_checks | At least two check_tool events with tool_decision == BLOCK and status == blocked | Repeated blocked tool checks. Tool and agent identities are unavailable. |
| repeated_blocked_data_checks | At least two check_data events with recommended_action == BLOCK and status == blocked | Repeated blocked data checks. The finding does not identify data classification or destination. |
| high_risk_analysis_burst | At least two analyze events with risk score at or above threshold or severity HIGH/CRITICAL | A burst of high-risk analyses that warrants investigation. This does not establish an attack. |

All rules require multiple events. A qualifying high-risk analysis is counted once even if both its score and severity meet the rule. Missing scores remain missing; UNKNOWN severity does not qualify by itself. No rule infers prompt-injection-to-tool sequences, exfiltration, a particular actor, tool, or destination.

## Configuration and bounds

Defaults:

| Setting | Default | Allowed range |
|---|---:|---:|
| max_events | 1,000 | 2-10,000 |
| analysis_window_seconds | 300 | 1-86,400 |
| minimum_pattern_events | 2 | 2-10,000 and no more than max_events |
| high_risk_minimum_events | 2 | 2-10,000 and no more than max_events |
| high_risk_score_threshold | 70 | 0-100 |
| max_findings | 3 | 1-3 |

Invalid configuration raises Pydantic validation errors at construction. The maximum event count is enforced while consuming the iterable: the analyzer reads at most max_events + 1 items. If the extra item exists, it returns analysis_status=limit_exceeded, an event_limit_exceeded code, and no partial findings.

Malformed event types, fields, timestamps, timezone information, iterator failures, or reference timestamps return the fixed invalid_input report. The report does not include exception text, validation details, or source representations. If max_findings is below the number of matching rules, findings are retained in fixed rule order (tool checks, data checks, then high-risk analyses); total_findings and findings_truncated signal that output was capped.

## Time-window semantics

All timestamps must be timezone-aware. They are normalized to UTC. When reference_time is supplied, it must also be timezone-aware and is the inclusive end of the analysis window. Without it, the latest event timestamp is used, so identical input produces identical output without depending on wall-clock time.

The window is inclusive: [reference_time - analysis_window_seconds, reference_time]. Events outside that interval are excluded from rule counts. Equal timestamps are treated as unordered; the analyzer does not infer sequence or causality.

## Duplicate events

The schema has no stable event ID or sequence number. Therefore, the analyzer does not deduplicate. Each input record counts once, including identical records. Callers should supply one snapshot without accidental repeated insertion; the analyzer cannot safely distinguish a duplicate delivery from two legitimate identical records.

## Synthetic example

Two synthetic blocked tool checks inside the configured window produce a report with:

- analysis_status=complete
- one finding with rule ID repeated_blocked_tool_checks
- category=suspicious_pattern and review_required=true
- matched_event_count=2
- first and last matching timestamps
- numeric threshold evidence and a fixed explanation

No request ID, tool name, arguments, prompt, detector indicator, policy reason, or enforcement action appears in the finding.

## Privacy and integration limits

Report models use explicit fields and fixed explanations. The analyzer omits request IDs and ignores fields that are not needed by the rules. It never serializes an entire source event. Malformed input failures use fixed status and error codes without reflecting input values.

The monitoring schema does not expose reliable agent identity, tool name, arguments, data classification, destination, detailed detector category, shared cross-event correlation ID, or sequence number. Stronger sequence or actor correlation would require separately approved, sanitized schema changes. This module does not modify the AuditLogger, API, SecurityService, Risk Engine, Threat Detector, or dashboard.

Findings only invite review. A caller or separately authorized workflow must decide what action, if any, is appropriate.

## Tests

Run the isolated tests first:

    python -m pytest tests/security/test_incident_analyzer.py -q
    python -m pytest tests/test_monitoring.py -q
    python -m pytest tests/security/test_security_pipeline.py tests/security/test_risk_engine.py tests/test_security.py -q

The unit tests use synthetic events and make no external requests.
