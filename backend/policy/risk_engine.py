"""Safe interface placeholder for future risk scoring."""

from typing import Literal

from pydantic import BaseModel

from backend.detector.threat_detector import ThreatAssessment


class RiskAssessment(BaseModel):
    """Unassessed risk result; no score is implied by the placeholder."""

    status: Literal["not_implemented"] = "not_implemented"
    risk_score: None = None
    severity: Literal["UNKNOWN"] = "UNKNOWN"


class RiskEngine:
    """Expose a risk assessment contract without assigning a score."""

    def assess(self, assessment: ThreatAssessment) -> RiskAssessment:
        """Return an unassessed result until threat and risk logic exists."""
        del assessment
        return RiskAssessment()
