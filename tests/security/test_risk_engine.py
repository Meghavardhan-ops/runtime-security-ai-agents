"""Unit tests for deterministic, side-effect-free risk scoring."""

from typing import cast

from pydantic import BaseModel, Field

from backend.detector.threat_detector import ThreatAssessment
from backend.policy.risk_engine import RiskAssessment, RiskEngine


class FutureThreatAssessment(BaseModel):
    """Test contract showing optional detector fields supported in future."""

    status: str = "analyzed"
    threat: str = "benign"
    indicators: list[str] = Field(default_factory=list)
    risk_score: int | float | None = None
    severity: str | None = None


def assessment(
    threat: str,
    indicators: list[str] | None = None,
) -> ThreatAssessment:
    """Construct detector labels not yet admitted by its current Literal type."""
    return ThreatAssessment.model_construct(
        status="not_implemented",
        threat=threat,
        indicators=indicators or [],
    )


def score(threat: str, indicators: list[str] | None = None) -> RiskAssessment:
    return RiskEngine().assess(assessment(threat, indicators))


def test_not_assessed_fails_closed() -> None:
    result = RiskEngine().assess(ThreatAssessment())

    assert result.status == "fail_closed"
    assert result.risk_score == 100
    assert result.severity == "CRITICAL"
    assert result.recommended_action == "BLOCK"
    assert result.reasons == [
        "Threat assessment is unavailable; fail-closed security decision."
    ]
    assert result.source_category == "not_assessed"


def test_unassessed_assessment_can_use_a_validated_detected_category() -> None:
    result = RiskEngine().assess(ThreatAssessment(), threat_category="benign")

    assert result.status == "scored"
    assert (result.risk_score, result.severity, result.recommended_action) == (
        0,
        "LOW",
        "ALLOW",
    )
    assert result.source_category == "benign"


def test_detected_category_does_not_double_count_its_indicators() -> None:
    assessment_with_detector_evidence = ThreatAssessment(
        indicators=["credential_access", "sensitive_file_access"]
    )

    result = RiskEngine().assess(
        assessment_with_detector_evidence,
        threat_category="credential_theft",
    )

    assert result.risk_score == 90
    assert result.severity == "CRITICAL"
    assert result.recommended_action == "BLOCK"
    assert result.source_category == "credential_theft"
    assert result.reasons == [
        "Threat category 'credential_theft' has base score 90."
    ]


def test_unknown_category_override_fails_closed() -> None:
    result = RiskEngine().assess(
        ThreatAssessment(), threat_category="future_unknown_category"
    )

    assert result.status == "fail_closed"
    assert result.source_category == "future_unknown_category"
    assert (result.risk_score, result.severity, result.recommended_action) == (
        100,
        "CRITICAL",
        "BLOCK",
    )


def test_suspicious_threat() -> None:
    result = score("suspicious")

    assert (result.risk_score, result.severity, result.recommended_action) == (
        35,
        "MEDIUM",
        "REVIEW",
    )


def test_prompt_injection_threat() -> None:
    result = score("prompt_injection")

    assert (result.risk_score, result.severity, result.recommended_action) == (
        70,
        "HIGH",
        "REVIEW",
    )


def test_tool_abuse_threat() -> None:
    result = score("tool_abuse")

    assert (result.risk_score, result.severity, result.recommended_action) == (
        75,
        "HIGH",
        "REVIEW",
    )


def test_credential_theft_threat() -> None:
    result = score("credential_theft")

    assert (result.risk_score, result.severity, result.recommended_action) == (
        90,
        "CRITICAL",
        "BLOCK",
    )


def test_data_exfiltration_threat() -> None:
    result = score("data_exfiltration")

    assert (result.risk_score, result.severity, result.recommended_action) == (
        95,
        "CRITICAL",
        "BLOCK",
    )


def test_recognized_indicators_add_bounded_deterministic_adjustments() -> None:
    result = score(
        "suspicious",
        ["unauthorized_tool", "external_network_request", "unauthorized_tool"],
    )

    assert result.risk_score == 48
    assert result.reasons == [
        "Threat category 'suspicious' has base score 35.",
        "Recognized indicator 'external_network_request' adds 5 points.",
        "Recognized indicator 'unauthorized_tool' adds 8 points.",
    ]


def test_low_classification_allows() -> None:
    result = score("benign")

    assert (result.risk_score, result.severity, result.recommended_action) == (
        0,
        "LOW",
        "ALLOW",
    )


def test_medium_classification() -> None:
    future = FutureThreatAssessment(threat="benign", risk_score=50)
    result = RiskEngine().assess(cast(ThreatAssessment, future))

    assert (result.risk_score, result.severity, result.recommended_action) == (
        50,
        "MEDIUM",
        "REVIEW",
    )


def test_high_classification() -> None:
    future = FutureThreatAssessment(threat="benign", risk_score=51)
    result = RiskEngine().assess(cast(ThreatAssessment, future))

    assert (result.risk_score, result.severity, result.recommended_action) == (
        51,
        "HIGH",
        "REVIEW",
    )


def test_critical_classification() -> None:
    future = FutureThreatAssessment(threat="benign", severity="critical")
    result = RiskEngine().assess(cast(ThreatAssessment, future))

    assert (result.risk_score, result.severity, result.recommended_action) == (
        76,
        "CRITICAL",
        "BLOCK",
    )


def test_score_never_falls_below_zero() -> None:
    future = FutureThreatAssessment(threat="benign", risk_score=-20)
    result = RiskEngine().assess(cast(ThreatAssessment, future))

    assert result.risk_score == 0
    assert result.risk_score >= 0


def test_score_never_exceeds_100() -> None:
    result = score(
        "data_exfiltration",
        [
            "instruction_override",
            "system_prompt_extraction",
            "credential_access",
            "sensitive_file_access",
            "external_data_exfiltration",
            "unauthorized_tool",
            "external_network_request",
        ],
    )

    assert result.risk_score == 100
    assert result.risk_score <= 100


def test_future_detector_score_is_clamped_even_when_very_large() -> None:
    future = FutureThreatAssessment(threat="benign", risk_score=10**1000)
    result = RiskEngine().assess(cast(ThreatAssessment, future))

    assert result.risk_score == 100
    assert result.severity == "CRITICAL"
    assert result.recommended_action == "BLOCK"


def test_output_is_deterministic() -> None:
    threat = assessment("suspicious", ["unauthorized_tool", "credential_access"])

    first = RiskEngine().assess(threat)
    second = RiskEngine().assess(threat)

    assert first.model_dump() == second.model_dump()


def test_empty_indicators_do_not_change_the_base_score() -> None:
    result = score("benign", [])

    assert result.risk_score == 0
    assert result.reasons == ["Threat category 'benign' has base score 0."]


def test_unknown_threat_category_fails_closed() -> None:
    result = score("future_unknown_category")

    assert result.status == "fail_closed"
    assert result.source_category == "future_unknown_category"
    assert result.risk_score == 100
    assert result.severity == "CRITICAL"
    assert result.recommended_action == "BLOCK"
    assert "Unknown threat category" in result.reasons[0]


def test_future_detector_fields_can_only_raise_risk() -> None:
    future = FutureThreatAssessment(
        threat="suspicious",
        indicators=["unauthorized_tool"],
        risk_score=20,
        severity="high",
    )

    result = RiskEngine().assess(cast(ThreatAssessment, future))

    assert result.risk_score == 51
    assert result.severity == "HIGH"
    assert result.recommended_action == "REVIEW"
