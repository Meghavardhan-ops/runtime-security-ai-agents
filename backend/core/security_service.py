"""Orchestration for the Security API's check-only component interfaces."""

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from backend.detector.models import DetectionResult
from backend.detector.threat_detector import ThreatDetector
from backend.gateway.input_gateway import InputGateway, SecurityInput, SecurityInputRequest
from backend.gateway.tool_gateway import ToolGateway
from backend.monitor.audit_logger import AuditLogger
from backend.policy.data_classifier import DataClassifier
from backend.policy.policy_engine import PolicyEngine, SecurityDecision
from backend.policy.risk_engine import RiskEngine


class SecurityAnalysis(BaseModel):
    """Risk-engine placeholder response with the detector's separate result."""

    input_id: UUID
    analysis_status: Literal["not_implemented"] = "not_implemented"
    risk_score: int | None = None
    severity: Literal["UNKNOWN"] = "UNKNOWN"
    threat: Literal["not_assessed"] = "not_assessed"
    action: Literal["REVIEW"] = "REVIEW"
    indicators: list[str] = Field(default_factory=list)
    reason: str = (
        "Risk scoring is not implemented; see detection_result for detector output."
    )
    detection_result: DetectionResult


class SecurityService:
    """Coordinate security component stubs without executing requested actions."""

    def __init__(
        self,
        input_gateway: InputGateway | None = None,
        threat_detector: ThreatDetector | None = None,
        risk_engine: RiskEngine | None = None,
        data_classifier: DataClassifier | None = None,
        policy_engine: PolicyEngine | None = None,
        tool_gateway: ToolGateway | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.input_gateway = input_gateway or InputGateway()
        self.threat_detector = threat_detector or ThreatDetector()
        self.risk_engine = risk_engine or RiskEngine()
        self.data_classifier = data_classifier or DataClassifier()
        self.policy_engine = policy_engine or PolicyEngine()
        self.tool_gateway = tool_gateway or ToolGateway(self.policy_engine)
        self.audit_logger = audit_logger or AuditLogger()

    def analyze(self, request: SecurityInputRequest) -> SecurityAnalysis:
        """Re-run ingress normalization before passing input to safe stubs."""
        normalized_input = self.input_gateway.normalize(request)
        threat_assessment = self.threat_detector.analyze(normalized_input)
        risk_assessment = self.risk_engine.assess(threat_assessment)
        response = SecurityAnalysis(
            input_id=normalized_input.id,
            risk_score=risk_assessment.risk_score,
            severity=risk_assessment.severity,
            threat=threat_assessment.threat,
            indicators=threat_assessment.indicators,
            detection_result=threat_assessment.detection_result,
        )
        self.audit_logger.record(
            "analyze", response.action, None, request_id=normalized_input.id
        )
        return response

    def check_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> SecurityDecision:
        """Check a tool request without invoking it."""
        decision = self.tool_gateway.check(tool_name, arguments)
        self.audit_logger.record("check_tool", decision.action, decision.allowed)
        return decision

    def check_data(self, data_type: str, destination: str) -> SecurityDecision:
        """Check caller-supplied data labels without moving or classifying data."""
        classification = self.data_classifier.classify(data_type, destination)
        decision = self.policy_engine.check_data(classification)
        self.audit_logger.record("check_data", decision.action, decision.allowed)
        return decision

    def check_action(self, action: str, target: str) -> SecurityDecision:
        """Check an action request without contacting or modifying its target."""
        del target
        decision = self.policy_engine.check_action(action)
        self.audit_logger.record("check_action", decision.action, decision.allowed)
        return decision
