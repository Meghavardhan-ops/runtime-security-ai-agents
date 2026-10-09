"""Focused tests for metadata-only runtime monitoring."""

from uuid import uuid4

from fastapi.testclient import TestClient

from backend.main import app
from backend.monitor.audit_logger import AuditLogger

client = TestClient(app)
SECURITY_URL = "/api/v1/security"


def test_audit_logger_stores_only_allowlisted_metadata() -> None:
    logger = AuditLogger()
    secret = "sk-test-secret-bearer-token-raw-content"
    logger.record(
        "analyze", secret, None, request_id=uuid4(), source_type="text",
        threat_category=secret, severity=secret, risk_score=1000,
        policy_decision=secret, tool_decision=secret,
    )

    serialized = str([event.model_dump(mode="json") for event in logger.events()])
    assert secret not in serialized
    event = logger.events()[0]
    assert event.source_type == "text"
    assert event.threat_category == "unknown"
    assert event.severity == "UNKNOWN"
    assert event.risk_score is None
    assert event.recommended_action == "REVIEW"
    assert event.policy_decision is None
    assert event.tool_decision is None


def test_monitoring_api_records_decision_metadata_without_sensitive_values() -> None:
    raw_content = "RAW-REQUEST sk-1234567890-secret"
    raw_argument = "RAW-TOOL-ARGUMENT bearer ABCDEFGHIJKLMNOP"
    client.post(
        f"{SECURITY_URL}/analyze",
        json={"source_type": "file", "source_name": "safe.txt", "content": raw_content},
    )
    tool_result = client.post(
        f"{SECURITY_URL}/check-tool",
        json={"tool_name": "file_read", "arguments": {"token": raw_argument}},
    )
    assert tool_result.status_code == 200

    response = client.get(f"{SECURITY_URL}/monitoring")
    assert response.status_code == 200
    payload = response.text
    assert raw_content not in payload
    assert raw_argument not in payload
    assert "sk-1234567890-secret" not in payload
    assert "ABCDEFGHIJKLMNOP" not in payload
    events = response.json()
    analysis = next(item for item in events if item["event_type"] == "analyze")
    tool_event = next(item for item in events if item["event_type"] == "check_tool")
    assert analysis["source_type"] == "file"
    assert analysis["status"] == "allowed"
    assert analysis["risk_score"] == 0
    assert analysis["severity"] == "LOW"
    assert analysis["recommended_action"] == "ALLOW"
    assert analysis["policy_decision"] == "ALLOW"
    assert tool_event["status"] == "blocked"
    assert tool_event["policy_decision"] == "BLOCK"
    assert tool_event["tool_decision"] == "BLOCK"


def test_monitoring_summary_counts_recorded_decisions() -> None:
    before = client.get(f"{SECURITY_URL}/monitoring/summary").json()
    for action in ("check-tool", "check-data", "check-action"):
        if action == "check-tool":
            body = {"tool_name": "file_read", "arguments": {}}
        elif action == "check-data":
            body = {"data_type": "public", "destination": "local"}
        else:
            body = {"action": "read", "target": "local"}
        assert client.post(f"{SECURITY_URL}/{action}", json=body).status_code == 200

    after = client.get(f"{SECURITY_URL}/monitoring/summary")
    assert after.status_code == 200
    summary = after.json()
    assert summary["total_events"] == before["total_events"] + 3
    assert summary["blocked_events"] == before["blocked_events"] + 3
    assert summary["allowed_events"] == before["allowed_events"]
    assert summary["policy_decisions"]["BLOCK"] >= 3


def test_empty_monitoring_state_returns_zero_summary_and_empty_events() -> None:
    logger = AuditLogger()
    assert logger.events() == []
    assert logger.summary() == {
        "total_events": 0,
        "allowed_events": 0,
        "review_events": 0,
        "blocked_events": 0,
        "threat_categories": {},
        "severities": {},
        "policy_decisions": {},
        "source_types": {},
    }


def test_summary_aggregates_status_category_severity_and_source_type() -> None:
    logger = AuditLogger()
    logger.record(
        "analyze", "ALLOW", True, source_type="email",
        threat_category="not_assessed", severity="LOW", risk_score=4,
    )
    logger.record(
        "analyze", "REVIEW", None, source_type="web",
        threat_category="not_assessed", severity="MEDIUM",
    )
    logger.record(
        "check_tool", "BLOCK", False, policy_decision="BLOCK",
    )

    assert logger.summary() == {
        "total_events": 3,
        "allowed_events": 1,
        "review_events": 1,
        "blocked_events": 1,
        "threat_categories": {"not_assessed": 2, "unknown": 1},
        "severities": {"LOW": 1, "MEDIUM": 1, "UNKNOWN": 1},
        "policy_decisions": {"BLOCK": 1},
        "source_types": {"email": 1, "web": 1},
    }


def test_monitoring_limit_validation() -> None:
    assert client.get(f"{SECURITY_URL}/monitoring?limit=0").status_code == 422
    assert client.get(f"{SECURITY_URL}/monitoring?limit=1001").status_code == 422
