"""Orchestration for the Security API's check-only component interfaces."""

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from backend.detector.models import DetectionResult
from backend.detector.threat_detector import ThreatDetector
from backend.gateway.input_gateway import InputGateway, SecurityInput, SecurityInputRequest
from backend.gateway.tool_gateway import ToolGateway
from backend.monitor.audit_logger import AuditLogger
from backend.policy.agent_permissions import AgentPermissionRegistry
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
    analysis_status: Literal["analyzed", "fail_closed", "not_implemented"] = "not_implemented"
    risk_score: int | None = Field(default=None, ge=0, le=100)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"] = "UNKNOWN"
    threat: Literal[
        "benign", "prompt_injection", "data_exfiltration", "credential_theft",
        "tool_abuse", "suspicious", "not_assessed",
    ] = "not_assessed"
    action: Literal["ALLOW", "REVIEW", "BLOCK"] = "REVIEW"
    indicators: list[str] = Field(default_factory=list)
    reason: str = "Threat has not been assessed; risk remains unassessed."
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
        agent_permissions: AgentPermissionRegistry | None = None,
    ) -> None:
        self.input_gateway = input_gateway or InputGateway()
        self.threat_detector = threat_detector or ThreatDetector()
        self.risk_engine = risk_engine or RiskEngine()
        self.data_classifier = data_classifier or DataClassifier()
        self.dlp_engine = dlp_engine or DLPEngine()
        self.policy_engine = policy_engine or PolicyEngine()
        self.tool_gateway = tool_gateway or ToolGateway(self.policy_engine)
        self.audit_logger = audit_logger or AuditLogger()
        self.agent_permissions = agent_permissions or AgentPermissionRegistry()

    def analyze(self, request: SecurityInputRequest) -> SecurityAnalysis:
        """Re-run ingress normalization before passing input to safe stubs."""
        normalized_input = self.input_gateway.normalize(request)
        threat_assessment = self.threat_detector.analyze(normalized_input)
        detection_result = threat_assessment.detection_result
        detected_category = (
            detection_result.category if detection_result is not None else None
        )
        risk_assessment = self.risk_engine.assess(
            threat_assessment,
            threat_category=detected_category,
            detection_result=detection_result,
        )
        policy_decision = self.policy_engine.evaluate_risk(risk_assessment)
        final_action = self._strictest_action(
            risk_assessment.recommended_action, policy_decision.action
        )
        if policy_decision.action == final_action:
            # When policy establishes the final restriction, retain its
            # configured explanation (especially for policy BLOCK).
            final_reason = policy_decision.reason
        else:
            category = detection_result.category if detection_result is not None else "not_assessed"
            final_reason = (
                f"Final action {final_action} is required by the Risk Engine "
                f"(score={risk_assessment.risk_score}, severity={risk_assessment.severity}, "
                f"detector_category={category}); the Policy Engine returned "
                f"{policy_decision.action}."
            )
        response = SecurityAnalysis(
            input_id=normalized_input.id,
            analysis_status=("analyzed" if risk_assessment.status == "scored" else "fail_closed"),
            risk_score=risk_assessment.risk_score,
            severity=risk_assessment.severity,
            action=final_action,
            threat=detected_category or "not_assessed",
            indicators=threat_assessment.indicators,
            reason=final_reason,
            detection_result=threat_assessment.detection_result,
        )
        self.audit_logger.record(
            "analyze",
            response.action,
            response.action == "ALLOW",
            request_id=normalized_input.id,
            source_type=normalized_input.source_type,
            threat_category=response.threat,
            severity=response.severity,
            risk_score=response.risk_score,
            policy_decision=policy_decision.action,
        )
        return response

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

    def check_agent_tool(
        self, agent_id: str, tool_name: str, arguments: dict[str, Any]
    ) -> SecurityDecision:
        """Authorize a tool against demo agent scope and normal policy; never execute."""
        profile = self.agent_permissions.get(agent_id)
        if profile is None:
            decision = self._agent_block("Unknown agent; tool access denied.")
            self._record_agent_decision(
                "check_agent_tool", decision, agent_id, "tool", tool_name
            )
            return decision

        normalized_tool = tool_name.strip().casefold() if isinstance(tool_name, str) else ""
        if normalized_tool not in profile.allowed_tools:
            decision = self._agent_block("Tool is outside this agent's permissions.")
            self._record_agent_decision(
                "check_agent_tool", decision, agent_id, "tool", tool_name
            )
            return decision

        decision = self.tool_gateway.check(tool_name, arguments)
        self._record_agent_decision(
            "check_agent_tool", decision, agent_id, "tool", tool_name,
            policy_decision=decision.action,
            tool_decision=decision.action,
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
        dlp_result, policy_decision, _ = self._evaluate_data_content(
            data_type, destination, content
        )
        decision = (
            policy_decision
            if self.data_classifier.is_available
            else self._review_unverified_classification(
                policy_decision,
                "Data classification is unverified; data flow requires review.",
            )
        )
        self.audit_logger.record(
            "check_data", decision.action, decision.allowed,
            policy_decision=policy_decision.action,
        )
        return dlp_result, decision

    def check_agent_data_with_content(
        self, agent_id: str, data_type: str, destination: str, content: object
    ) -> tuple[DLPResult, SecurityDecision]:
        """Scan data, enforce the agent's classification scope, then apply policy."""
        profile = self.agent_permissions.get(agent_id)
        if profile is None:
            scan = self._scan_data_content(content)
            decision = self._agent_block("Unknown agent; data access denied.")
            self._record_agent_decision(
                "check_agent_data", decision, agent_id, "data", data_type
            )
            return scan, decision

        dlp_result, policy_decision, effective_data_type = self._evaluate_data_content(
            data_type, destination, content
        )
        if policy_decision.action == "BLOCK":
            # Preserve the policy engine's strongest result before applying
            # agent-scope and classifier-availability restrictions.
            decision = policy_decision
        elif effective_data_type not in profile.allowed_data_classifications:
            decision = self._agent_block(
                "Data classification is outside this agent's permissions."
            )
        elif not getattr(self.data_classifier, "is_available", False):
            # DLP detects known patterns, but a no-match result cannot verify
            # the caller's label or establish that the content is public.
            decision = self._review_unverified_classification(
                policy_decision,
                "Data classification is unverified; agent data access requires review.",
            )
        else:
            decision = policy_decision
        self._record_agent_decision(
            "check_agent_data", decision, agent_id, "data", effective_data_type,
            policy_decision=policy_decision.action,
        )
        return dlp_result, decision

    def _evaluate_data_content(
        self, data_type: str, destination: str, content: object
    ) -> tuple[DLPResult, SecurityDecision, str]:
        dlp_result = self._scan_data_content(content)
        effective_data_type = self._data_type_after_scan(
            data_type, destination, dlp_result
        )
        classification = self.data_classifier.classify(
            effective_data_type, destination
        )
        decision = self.policy_engine.check_data(classification)
        return dlp_result, decision, effective_data_type

    def _scan_data_content(self, content: object) -> DLPResult:
        try:
            return self.dlp_engine.scan(content)
        except Exception:
            return DLPResult(
                data_type="unknown",
                classification="unknown",
                indicators=(),
                contains_sensitive_data=None,
                severity="UNKNOWN",
                scan_status="invalid_input",
            )

    def _agent_block(self, reason: str) -> SecurityDecision:
        policy_status = (
            "available"
            if self.policy_engine.is_available
            else "unavailable"
        )
        return SecurityDecision(
            allowed=False,
            action="BLOCK",
            reason=reason,
            policy_status=policy_status,
        )

    @staticmethod
    def _review_unverified_classification(
        policy_decision: SecurityDecision, reason: str
    ) -> SecurityDecision:
        """Hold otherwise-allowed data for review while preserving policy BLOCK."""
        if policy_decision.action == "BLOCK":
            return policy_decision
        return SecurityDecision(
            allowed=False,
            action="REVIEW",
            reason=reason,
            policy_status=policy_decision.policy_status,
        )

    def _record_agent_decision(
        self,
        event: Literal["check_agent_tool", "check_agent_data"],
        decision: SecurityDecision,
        agent_id: str,
        permission_kind: Literal["tool", "data"],
        permission_subject: str,
        *,
        policy_decision: str | None = None,
        tool_decision: str | None = None,
    ) -> None:
        self.audit_logger.record(
            event,
            decision.action,
            decision.allowed,
            policy_decision=policy_decision,
            tool_decision=tool_decision,
            agent_id=agent_id,
            permission_kind=permission_kind,
            permission_subject=permission_subject,
        )

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

    @staticmethod
    def _strictest_action(*actions: str) -> Literal["ALLOW", "REVIEW", "BLOCK"]:
        rank = {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}
        return max(actions, key=lambda action: rank.get(action, 2))  # fail closed
