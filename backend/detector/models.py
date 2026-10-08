"""Structured, preliminary threat-detection results."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

DetectionCategory = Literal[
    "benign",
    "prompt_injection",
    "data_exfiltration",
    "credential_theft",
    "tool_abuse",
    "suspicious",
]
DetectionSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
RecommendedAction = Literal["ALLOW", "REVIEW", "BLOCK"]


class DetectionResult(BaseModel):
    """Evidence-backed detector output for a later risk and policy pipeline."""

    model_config = ConfigDict(extra="forbid")

    category: DetectionCategory
    severity: DetectionSeverity
    risk_score: int = Field(ge=0, le=100)
    indicators: list[str] = Field(default_factory=list)
    recommended_action: RecommendedAction

