"""Compatibility interface used by the existing SecurityService."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

from backend.detector.detector import Detector, DetectionResult

if TYPE_CHECKING:
    from backend.gateway.input_gateway import SecurityInput


class ThreatAssessment(BaseModel):
    """Legacy wrapper retaining the service contract and exposing detection.

    ``detection_result`` is optional only to keep direct construction of the
    legacy model compatible. ``ThreatDetector.analyze`` always supplies it.
    """

    # Retain legacy values for direct construction; analyze() reports analyzed.
    status: Literal["analyzed", "not_assessed", "not_implemented"] = "not_implemented"
    threat: Literal[
        "benign", "prompt_injection", "data_exfiltration", "credential_theft",
        "tool_abuse", "suspicious", "not_assessed",
    ] = "not_assessed"
    indicators: list[str] = Field(default_factory=list)
    detection_result: DetectionResult | None = None


class ThreatDetector:
    """Analyze normalized input while preserving the established method shape."""

    def __init__(self, detector: Detector | None = None) -> None:
        self.detector = detector or Detector()

    def analyze(self, security_input: SecurityInput) -> ThreatAssessment:
        """Detect threats in the supplied content without touching its source."""
        result = self.detector.detect(
            security_input.content,
            source_type=security_input.source_type,
        )
        return ThreatAssessment(
            status="analyzed",
            threat=result.category,
            indicators=result.indicators,
            detection_result=result,
        )
