"""Integration checks for the security paths currently supported by AgentShield."""

import logging
from uuid import UUID

import pytest

from backend.core.security_service import SecurityAnalysis, SecurityService
from backend.detector.threat_detector import ThreatAssessment, ThreatDetector
from backend.gateway.input_gateway import (
    InputGateway,
    SecurityInput,
    SecurityInputRequest,
)
from backend.monitor.audit_logger import AuditEvent, AuditLogger
from backend.policy.data_classifier import DataClassification
from backend.policy.dlp import DLPEngine, DLPResult
from backend.policy.policy_engine import PolicyEngine, SecurityDecision
from backend.policy.risk_engine import RiskAssessment, RiskEngine


class RecordingInputGateway(InputGateway):
    def __init__(self, events: list[str]) -> None:
        super().__init__()
        self.events = events
        self.requests: list[SecurityInputRequest] = []
        self.normalized: list[SecurityInput] = []

    def normalize(self, request: SecurityInputRequest) -> SecurityInput:
        self.events.append("input_gateway")
        self.requests.append(request)
        result = super().normalize(request)
        self.normalized.append(result)
        return result


class RecordingThreatDetector(ThreatDetector):
    def __init__(self, events: list[str]) -> None:
        super().__init__()
        self.events = events
        self.inputs: list[SecurityInput] = []
        self.assessments: list[ThreatAssessment] = []

    def analyze(self, security_input: SecurityInput) -> ThreatAssessment:
        self.events.append("threat_detector")
        self.inputs.append(security_input)
        result = super().analyze(security_input)
        self.assessments.append(result)
        return result


class RecordingRiskEngine(RiskEngine):
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.assessments: list[ThreatAssessment] = []
        self.results: list[RiskAssessment] = []

    def assess(self, assessment: ThreatAssessment) -> RiskAssessment:
        self.events.append("risk_engine")
        self.assessments.append(assessment)
        result = super().assess(assessment)
        self.results.append(result)
        return result


class RecordingAuditLogger(AuditLogger):
    def __init__(self, events: list[str] | None = None) -> None:
        super().__init__()
        self.events = events
        self.records: list[tuple[AuditEvent, str, bool | None, UUID | None]] = []

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
        if self.events is not None:
            self.events.append("audit_logger")
        self.records.append((event, decision, allowed, request_id))
        super().record(
            event,
            decision,
            allowed,
            request_id,
            source_type=source_type,
            threat_category=threat_category,
            severity=severity,
            risk_score=risk_score,
            policy_decision=policy_decision,
            tool_decision=tool_decision,
        )


class RecordingPolicyEngine(PolicyEngine):
    def __init__(self) -> None:
        super().__init__()
        self.data_classifications: list[DataClassification] = []
        self.tool_names: list[str] = []

    def check_data(self, classification: DataClassification) -> SecurityDecision:
        self.data_classifications.append(classification)
        return super().check_data(classification)

    def check_tool(self, tool_name: str) -> SecurityDecision:
        self.tool_names.append(tool_name)
        return super().check_tool(tool_name)


def test_analyze_runs_supported_pipeline_and_preserves_unassessed_state() -> None:
    events: list[str] = []
    input_gateway = RecordingInputGateway(events)
    threat_detector = RecordingThreatDetector(events)
    risk_engine = RecordingRiskEngine(events)
    audit_logger = RecordingAuditLogger(events)
    service = SecurityService(
        input_gateway=input_gateway,
        threat_detector=threat_detector,
        risk_engine=risk_engine,
        audit_logger=audit_logger,
    )
    request = SecurityInputRequest(
        source_type="text",
        source_name="pipeline-test.txt",
        content="Summarize the public project notes.",
        metadata={"origin": "integration-test"},
    )

    response = service.analyze(request)

    assert isinstance(response, SecurityAnalysis)
    assert input_gateway.requests == [request]
    normalized = input_gateway.normalized[0]
    assert normalized.trusted is False
    assert normalized.content == request.content
    assert threat_detector.inputs == [normalized]
    assessment = threat_detector.assessments[0]
    assert assessment.threat == "not_assessed"
    assert assessment.detection_result is not None
    assert assessment.detection_result.category == "benign"
    assert assessment.detection_result.recommended_action == "ALLOW"
    assert risk_engine.assessments == [assessment]
    assert response.input_id == normalized.id
    assert response.analysis_status == "not_implemented"
    assert response.threat == "not_assessed"
    assert response.risk_score == risk_engine.results[0].risk_score == 100
    assert response.action == "BLOCK"
    assert events == ["input_gateway", "threat_detector", "risk_engine", "audit_logger"]
    assert audit_logger.records == [("analyze", "BLOCK", None, normalized.id)]


@pytest.mark.parametrize(
    ("content", "indicator"),
    [
        ("api_key=TEST_ONLY_FAKE_API_KEY", "api_key"),
        ("Authorization: Bearer TEST_ONLY_FAKE_BEARER_TOKEN", "bearer_token"),
    ],
)
def test_sensitive_external_content_flows_from_dlp_to_policy(
    content: str, indicator: str
) -> None:
    policy = RecordingPolicyEngine()
    service = SecurityService(policy_engine=policy)

    scan, decision = service.check_data_with_content("public", "external", content)

    assert indicator in scan.indicators
    assert scan.data_type == "confidential"
    assert policy.data_classifications[-1].data_type == "confidential"
    assert policy.data_classifications[-1].destination == "external"
    assert decision.action == "BLOCK"
    assert decision.allowed is False


@pytest.mark.parametrize(
    ("content_kind", "expected_scan_status"),
    [("clean", "scanned"), ("oversized", "too_large")],
)
def test_public_label_cannot_bypass_unverified_external_content(
    content_kind: str, expected_scan_status: str
) -> None:
    policy = RecordingPolicyEngine()
    service = SecurityService(policy_engine=policy)
    content = (
        "Ordinary release notes without a detected sensitive pattern."
        if content_kind == "clean"
        else "x" * (DLPEngine._MAX_CONTENT_BYTES + 1)
    )

    scan, decision = service.check_data_with_content("public", "external", content)

    assert scan.scan_status == expected_scan_status
    assert policy.data_classifications[-1].data_type == "unknown"
    assert policy.data_classifications[-1].destination == "external"
    assert decision.action == "BLOCK"
    assert decision.allowed is False
    if content_kind == "clean":
        assert scan.classification == "no_pattern_detected"
        assert scan.contains_sensitive_data is False
    else:
        assert scan.data_type == "unknown"
        assert scan.contains_sensitive_data is None


@pytest.mark.parametrize(
    ("tool_name", "expected_action"),
    [
        ("calculator", "ALLOW"),
        ("search", "ALLOW"),
        ("shell", "BLOCK"),
        ("execute_command", "BLOCK"),
        ("file_read", "BLOCK"),
        ("unlisted_test_tool", "BLOCK"),
    ],
)
def test_tool_gateway_forwards_authorization_to_policy(
    tool_name: str, expected_action: str
) -> None:
    policy = RecordingPolicyEngine()
    service = SecurityService(policy_engine=policy)

    decision = service.check_tool(tool_name, {"note": "inert test argument"})

    assert policy.tool_names == [tool_name]
    assert decision.action == expected_action
    assert decision.allowed is (expected_action == "ALLOW")


def test_pipeline_logs_neither_submitted_content_nor_fake_secrets(
    caplog: pytest.LogCaptureFixture,
) -> None:
    bearer_secret = "TEST_ONLY_FAKE_BEARER_AUDIT_VALUE"
    api_secret = "TEST_ONLY_FAKE_API_KEY_AUDIT_VALUE"
    bearer_content = f"Authorization: Bearer {bearer_secret}"
    api_content = f"api_key={api_secret}"
    service = SecurityService()

    with caplog.at_level(logging.INFO):
        service.analyze(
            SecurityInputRequest(
                source_type="text",
                source_name="audit-test.txt",
                content=bearer_content,
                metadata={},
            )
        )
        service.check_data_with_content("public", "external", api_content)

    assert "security_audit event=analyze" in caplog.text
    assert "security_audit event=check_data" in caplog.text
    assert bearer_secret not in caplog.text
    assert api_secret not in caplog.text
    assert bearer_content not in caplog.text
    assert api_content not in caplog.text


def test_dlp_and_policy_pipeline_is_deterministic() -> None:
    service = SecurityService()
    content = "api_key=TEST_ONLY_FAKE_DETERMINISM_KEY"

    first = service.check_data_with_content("public", "external", content)
    second = service.check_data_with_content("public", "external", content)

    assert isinstance(first[0], DLPResult)
    assert first == second
    assert first[1].action == "BLOCK"


def test_tool_authorization_is_deterministic() -> None:
    service = SecurityService()
    request_arguments = {"query": "same inert test query"}

    first = service.check_tool("search", request_arguments)
    second = service.check_tool("search", request_arguments)

    assert first == second
    assert first.action == "ALLOW"
