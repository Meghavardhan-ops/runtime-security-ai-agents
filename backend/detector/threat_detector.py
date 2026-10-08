"""Safe interface placeholder for the future threat detector."""

from typing import Literal

from pydantic import BaseModel, Field

from backend.gateway.input_gateway import SecurityInput


class ThreatAssessment(BaseModel):
    """Explicitly unassessed result until detector implementation exists."""

    status: Literal["not_implemented"] = "not_implemented"
    threat: Literal["not_assessed"] = "not_assessed"
    indicators: list[str] = Field(default_factory=list)


class ThreatDetector:
    """Expose the future detector contract without inspecting input content."""

    def analyze(self, security_input: SecurityInput) -> ThreatAssessment:
        """Return an unassessed result; this stub performs no detection."""
        del security_input
        return ThreatAssessment()
