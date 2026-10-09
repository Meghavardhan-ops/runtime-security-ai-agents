"""Orchestration for the Security API's check-only component interfaces."""

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from backend.detector.classifiers import classify_result
from backend.detector.models import DetectionResult
from backend.detector.threat_detector import ThreatAssessment, ThreatDetector
from backend.gateway.input_gateway import InputGateway, SecurityInput, SecurityInputRequest
from backend.gateway.tool_gateway import ToolGateway
from backend.monitor.audit_logger import AuditLogger
from backend.policy.data_classifier import DataClassifier
from backend.policy.dlp import DLPEngine, DLPResult
from backend.policy.policy_engine import PolicyEngine, SecurityDecision
from backend.policy.risk_engine import RiskEngine


class SecurityAnalysis(BaseModel):
    """Risk analysis response including detector and risk-engine results.

    The optional detection result preserves direct construction of this legacy
    response model; SecurityService.analyze always returns a populated result.
    """

    input_id: UUID
    analysis_status: Literal["not_implemented"] = "not_implemented"
    risk_score: int | None = Field(default=None, ge=0, le=100)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"] = "UNKNOWN"
    threat: Literal["not_assessed"] = "not_assessed"
    action: Literal["ALLOW", "REVIEW", "BLOCK"] = "REVIEW"
    indicators: list[str] = Field(default_factory=list)
    reason: str = "Threat detection is not implemented; risk remains unassessed."
    detection_result: DetectionResult | None = None


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
        dlp_engine: DLPEngine | None = None,
    ) -> None:
        self.input_gateway = input_gateway or InputGateway()
        self.threat_detector = threat_detector or ThreatDetector()
        self.risk_engine = risk_engine or RiskEngine()
        self.data_classifier = data_classifier or DataClassifier()
        self.dlp_engine = dlp_engine or DLPEngine()
        self.policy_engine = policy_engine or PolicyEngine()
        self.tool_gateway = tool_gateway or ToolGateway(self.policy_engine)
        self.audit_logger = audit_logger or AuditLogger()

    def analyze(self, request: SecurityInputRequest) -> SecurityAnalysis:
        """Re-run ingress normalization before passing input to safe stubs."""
        normalized_input = self.input_gateway.normalize(request)
        try:
            raw_assessment = self.threat_detector.analyze(normalized_input)
            if not isinstance(raw_assessment, ThreatAssessment):
                raise TypeError("detector returned an invalid assessment")
            threat_assessment = ThreatAssessment.model_validate(
                raw_assessment.model_dump()
            )
        except Exception:
            # Malformed or unvalidated detector output must never authorize a request.
            threat_assessment = ThreatAssessment()

        detection_result = self._validated_detection_result(
            threat_assessment.detection_result
        )
        if (
            detection_result is not None
            and threat_assessment.indicators != detection_result.indicators
        ):
            detection_result = None
        detected_category = (
            detection_result.category if detection_result is not None else None
        )
        risk_assessment = self.risk_engine.assess(
            threat_assessment,
            threat_category=detected_category,
        )
        response = SecurityAnalysis(
            input_id=normalized_input.id,
            risk_score=risk_assessment.risk_score,
            severity=risk_assessment.severity,
            action=risk_assessment.recommended_action,
            threat=threat_assessment.threat,
            indicators=(
                detection_result.indicators if detection_result is not None else []
            ),
            reason=" ".join(risk_assessment.reasons),
            detection_result=detection_result,
        )
        self.audit_logger.record(
            "analyze",
            response.action,
            None,
            request_id=normalized_input.id,
            source_type=normalized_input.source_type,
            threat_category=response.threat,
            severity=response.severity,
            risk_score=response.risk_score,
        )
        return response

    @staticmethod
    def _validated_detection_result(
        result: DetectionResult | None,
    ) -> DetectionResult | None:
        """Accept only typed detector output consistent with its evidence labels."""
        if not isinstance(result, DetectionResult):
            return None
        try:
            candidate = DetectionResult.model_validate(result.model_dump())
            canonical = classify_result(set(candidate.indicators))
        except Exception:
            return None
        return candidate if candidate == canonical else None

    def check_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> SecurityDecision:
        """Check a tool request without invoking it."""
        decision = self.tool_gateway.check(tool_name, arguments)
        self.audit_logger.record(
            "check_tool", decision.action, decision.allowed,
            policy_decision=decision.action, tool_decision=decision.action,
        )
        return decision

    def check_data(self, data_type: str, destination: str) -> SecurityDecision:
        """Check caller-supplied labels; they are not verified by the DLP scanner."""
        normalized_type = data_type.strip().casefold()
        normalized_destination = destination.strip().casefold()
        if normalized_destination == "external" and normalized_type != "confidential":
            # The labels-only API has no content to scan, so it cannot establish
            # that an externally-bound payload is safe to release.
            classification = self.data_classifier.classify("unknown", destination)
        else:
            classification = self.data_classifier.classify(data_type, destination)
        decision = self.policy_engine.check_data(classification)
        self.audit_logger.record(
            "check_data", decision.action, decision.allowed,
            policy_decision=decision.action,
        )
        return decision

    def check_data_with_content(
        self, data_type: str, destination: str, content: object
    ) -> tuple[DLPResult, SecurityDecision]:
        """Scan content, raise its policy label when needed, then consult policy.

        Caller labels remain separate from DLP results. Sensitive findings raise
        public/internal labels to confidential; unscannable content and external
        content without a finding are sent to policy as unknown and fail closed.
        """
        try:
            dlp_result = self.dlp_engine.scan(content)
        except Exception:
            dlp_result = DLPResult(
                data_type="unknown",
                classification="unknown",
                indicators=(),
                contains_sensitive_data=None,
                severity="UNKNOWN",
                scan_status="invalid_input",
            )

        effective_data_type = self._data_type_after_scan(
            data_type, destination, dlp_result
        )
        classification = self.data_classifier.classify(
            effective_data_type, destination
        )
        decision = self.policy_engine.check_data(classification)
        self.audit_logger.record(
            "check_data", decision.action, decision.allowed,
            policy_decision=decision.action,
        )
        return dlp_result, decision

    @staticmethod
    def _data_type_after_scan(
        data_type: str, destination: str, result: DLPResult
    ) -> str:
        if result.scan_status != "scanned":
            return "unknown"

        normalized = data_type.strip().casefold()
        normalized_destination = destination.strip().casefold()
        if normalized_destination == "external":
            if result.contains_sensitive_data is not True:
                # Pattern matching cannot certify that external content is public.
                return "unknown"
            if normalized in {"public", "internal", "confidential"}:
                return "confidential"
            return data_type

        if result.contains_sensitive_data is True and normalized in {
            "public",
            "internal",
        }:
            return "confidential"
        return data_type

    def check_action(self, action: str, target: str) -> SecurityDecision:
        """Check an action request without contacting or modifying its target."""
        del target
        decision = self.policy_engine.check_action(action)
        self.audit_logger.record(
            "check_action", decision.action, decision.allowed,
            policy_decision=decision.action,
        )
        return decision
