"""Compatibility interface used by the existing SecurityService."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

from backend.detector.detector import Detector, DetectionResult

if TYPE_CHECKING:
    from backend.gateway.input_gateway import SecurityInput


class ThreatAssessment(BaseModel):
    """Legacy wrapper retaining the service contract and exposing detection."""

    status: Literal["not_implemented"] = "not_implemented"
    threat: Literal["not_assessed"] = "not_assessed"
    indicators: list[str] = Field(default_factory=list)
    detection_result: DetectionResult


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
            indicators=result.indicators,
            detection_result=result,
        )
