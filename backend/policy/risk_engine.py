"""Pure deterministic risk scoring for structured threat assessments."""

import math
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from backend.detector.threat_detector import ThreatAssessment
from backend.detector.models import DetectionResult

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
RecommendedAction = Literal["ALLOW", "REVIEW", "BLOCK"]

THREAT_BASE_SCORES: dict[str, int] = {
    "benign": 0,
    "suspicious": 35,
    "prompt_injection": 70,
    "tool_abuse": 75,
    "credential_theft": 90,
    "data_exfiltration": 95,
}

INDICATOR_ADJUSTMENTS: dict[str, int] = {
    "instruction_override": 8,
    "system_prompt_extraction": 8,
    "credential_access": 10,
    "sensitive_file_access": 5,
    "external_data_exfiltration": 10,
    "unauthorized_tool": 8,
    "external_network_request": 5,
}

SEVERITY_SCORE_FLOORS: dict[str, int] = {
    "low": 0,
    "medium": 26,
    "high": 51,
    "critical": 76,
}

UNKNOWN_ASSESSMENT_REASON = (
    "Threat assessment is unavailable; fail-closed security decision."
)


class RiskAssessment(BaseModel):
    """Structured score and recommended response for one threat assessment."""

    model_config = ConfigDict(frozen=True)

    status: Literal["scored", "fail_closed"]
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    recommended_action: RecommendedAction
    reasons: list[str]
    source_category: str


class RiskEngine:
    """Score only supplied threat metadata; perform no I/O or content inspection."""

    def assess(
        self,
        assessment: ThreatAssessment,
        *,
        threat_category: str | None = None,
        detection_result: DetectionResult | None = None,
    ) -> RiskAssessment:
        """Return a deterministic risk result from threat and indicator labels.

        A trusted caller may provide the category from a validated detector
        result. When it is absent, the legacy assessment field is used so
        unassessed inputs continue to fail closed.
        """
        validated_result = detection_result
        if validated_result is None:
            candidate = getattr(assessment, "detection_result", None)
            if isinstance(candidate, DetectionResult):
                validated_result = candidate
        source_category = self._normalize_label(
            threat_category
            if threat_category is not None
            else validated_result.category
            if validated_result is not None
            else getattr(assessment, "threat", None)
        ) or "not_assessed"
        base_score = THREAT_BASE_SCORES.get(source_category)
        if base_score is None:
            return self._fail_closed(
                source_category,
                UNKNOWN_ASSESSMENT_REASON
                if source_category == "not_assessed"
                else "Unknown threat category; fail-closed security decision.",
            )

        score = base_score
        reasons = [f"Threat category '{source_category}' has base score {base_score}."]

        # A validated detector category already summarizes the detector's
        # evidence. Applying the legacy indicator additions again would count
        # that same evidence twice. Direct legacy assessments keep their
        # additive indicator scoring behavior.
        indicators = (
            ()
            if threat_category is not None
            else getattr(assessment, "indicators", ()) or ()
        )
        recognized_indicators = {
            normalized
            for indicator in indicators
            if (normalized := self._normalize_label(indicator))
            in INDICATOR_ADJUSTMENTS
        }
        for indicator in sorted(recognized_indicators):
            adjustment = INDICATOR_ADJUSTMENTS[indicator]
            score += adjustment
            reasons.append(f"Recognized indicator '{indicator}' adds {adjustment} points.")

        future_fields = self._future_detector_adjustments(assessment)
        if future_fields is None:
            return self._fail_closed(
                source_category,
                "Invalid detector-provided risk metadata; fail-closed security decision.",
            )
        detector_score, detector_severity, detector_reasons = future_fields
        if validated_result is not None:
            detector_score = max(detector_score or 0, validated_result.risk_score)
            validated_severity = self._normalize_label(validated_result.severity)
            floor = SEVERITY_SCORE_FLOORS[validated_severity]
            detector_score = max(detector_score, floor)
            detector_severity = validated_severity
        if detector_score is not None:
            if detector_score > score:
                reasons.append(
                    f"Detector-provided risk score raises the score to {detector_score}."
                )
            score = max(score, detector_score)
        if detector_severity is not None:
            severity_floor = SEVERITY_SCORE_FLOORS[detector_severity]
            if severity_floor > score:
                reasons.append(
                    f"Detector-provided severity '{detector_severity.upper()}' raises "
                    f"the minimum score to {severity_floor}."
                )
            score = max(score, severity_floor)
        reasons.extend(detector_reasons)

        risk_score = self._clamp(score)
        severity = self._severity_for(risk_score)
        action = self._action_for(severity)
        return RiskAssessment(
            status="scored",
            risk_score=risk_score,
            severity=severity,
            recommended_action=action,
            reasons=reasons,
            source_category=source_category,
        )

    @staticmethod
    def _normalize_label(value: object) -> str:
        """Normalize category labels and enum-like values deterministically."""
        if hasattr(value, "value"):
            value = getattr(value, "value")
        if not isinstance(value, str):
            return ""
        return value.strip().casefold().replace("-", "_").replace(" ", "_")

    @classmethod
    def _future_detector_adjustments(
        cls, assessment: ThreatAssessment
    ) -> tuple[int | None, str | None, list[str]] | None:
        """Read optional future detector score/severity fields conservatively."""
        reasons: list[str] = []
        detector_score: int | None = None

        raw_score = getattr(assessment, "risk_score", None)
        if raw_score is not None:
            if isinstance(raw_score, bool):
                return None
            if isinstance(raw_score, int):
                detector_score = cls._clamp(raw_score)
            elif isinstance(raw_score, float) and math.isfinite(raw_score):
                detector_score = cls._clamp(math.ceil(raw_score))
            else:
                return None
            if detector_score != raw_score:
                reasons.append(
                    f"Detector-provided risk score was bounded to {detector_score}."
                )

        raw_severity = getattr(assessment, "severity", None)
        detector_severity: str | None = None
        if raw_severity is not None:
            detector_severity = cls._normalize_label(raw_severity)
            if detector_severity not in SEVERITY_SCORE_FLOORS:
                return None
        return detector_score, detector_severity, reasons

    @staticmethod
    def _clamp(score: int) -> int:
        return max(0, min(100, score))

    @staticmethod
    def _severity_for(score: int) -> Severity:
        if score <= 25:
            return "LOW"
        if score <= 50:
            return "MEDIUM"
        if score <= 75:
            return "HIGH"
        return "CRITICAL"

    @staticmethod
    def _action_for(severity: Severity) -> RecommendedAction:
        if severity == "LOW":
            return "ALLOW"
        if severity == "CRITICAL":
            return "BLOCK"
        return "REVIEW"

    @classmethod
    def _fail_closed(cls, source_category: str, reason: str) -> RiskAssessment:
        return RiskAssessment(
            status="fail_closed",
            risk_score=100,
            severity="CRITICAL",
            recommended_action="BLOCK",
            reasons=[reason],
            source_category=source_category,
        )
