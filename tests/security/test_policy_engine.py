"""Tests for deterministic, fail-closed Policy Engine decisions."""

from pathlib import Path
from typing import Iterator
from uuid import uuid4

import pytest

from backend.policy.data_classifier import DataClassification
from backend.policy.policy_engine import PolicyEngine, SecurityDecision
from backend.policy.risk_engine import RiskAssessment


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine()


@pytest.fixture
def local_policy_path() -> Iterator[Path]:
    """Use a disposable file under the workspace, not the system temp folder."""
    path = Path(__file__).with_name(f".policy-test-{uuid4().hex}.yaml")
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)


def make_risk(
    *, score: int, severity: str, recommendation: str, status: str = "scored"
) -> RiskAssessment:
    return RiskAssessment(
        status=status,
        risk_score=score,
        severity=severity,  # type: ignore[arg-type]
        recommended_action=recommendation,  # type: ignore[arg-type]
        reasons=["test risk assessment"],
        source_category="test",
    )


def test_allowed_tool(engine: PolicyEngine) -> None:
    decision = engine.check_tool("calculator")

    assert decision.allowed is True
    assert decision.action == "ALLOW"


def test_denied_tool(engine: PolicyEngine) -> None:
    decision = engine.check_tool("shell")

    assert decision.allowed is False
    assert decision.action == "BLOCK"


def test_unknown_tool_is_denied(engine: PolicyEngine) -> None:
    decision = engine.check_tool("unlisted_tool")

    assert decision.allowed is False
    assert decision.action == "BLOCK"


@pytest.mark.parametrize("tool_name", ["", "   ", None])
def test_empty_or_invalid_tool_is_denied(engine: PolicyEngine, tool_name: object) -> None:
    decision = engine.check_tool(tool_name)  # type: ignore[arg-type]

    assert decision.allowed is False
    assert decision.action == "BLOCK"


def test_confidential_data_to_external_is_blocked(engine: PolicyEngine) -> None:
    decision = engine.check_data(
        DataClassification(data_type="confidential", destination="external")
    )

    assert decision.action == "BLOCK"
    assert decision.allowed is False


def test_confidential_data_to_internal_follows_policy(engine: PolicyEngine) -> None:
    decision = engine.check_data(
        DataClassification(data_type="confidential", destination="internal")
    )

    assert decision.action == "REVIEW"
    assert decision.allowed is False


def test_unknown_data_type_is_denied(engine: PolicyEngine) -> None:
    decision = engine.check_data(
        DataClassification(data_type="unclassified", destination="internal")
    )

    assert decision.action == "BLOCK"
    assert decision.allowed is False


def test_unknown_destination_is_denied(engine: PolicyEngine) -> None:
    decision = engine.check_data(
        DataClassification(data_type="public", destination="unknown")
    )

    assert decision.action == "BLOCK"
    assert decision.allowed is False


def test_blocked_action(engine: PolicyEngine) -> None:
    decision = engine.check_action("delete_file")

    assert decision.action == "BLOCK"
    assert decision.allowed is False


def test_review_action(engine: PolicyEngine) -> None:
    decision = engine.check_action("review_report")

    assert decision.action == "REVIEW"
    assert decision.allowed is False


def test_allowed_action(engine: PolicyEngine) -> None:
    decision = engine.check_action("calculate")

    assert decision.action == "ALLOW"
    assert decision.allowed is True


def test_unknown_action_is_denied(engine: PolicyEngine) -> None:
    decision = engine.check_action("unknown_action")

    assert decision.action == "BLOCK"
    assert decision.allowed is False


@pytest.mark.parametrize(
    ("score", "severity", "recommendation", "expected"),
    [
        (0, "LOW", "ALLOW", "ALLOW"),
        (35, "MEDIUM", "REVIEW", "REVIEW"),
        (60, "HIGH", "REVIEW", "REVIEW"),
        (90, "CRITICAL", "BLOCK", "BLOCK"),
    ],
)
def test_risk_severity_and_score_decisions(
    engine: PolicyEngine,
    score: int,
    severity: str,
    recommendation: str,
    expected: str,
) -> None:
    decision = engine.evaluate_risk(
        make_risk(score=score, severity=severity, recommendation=recommendation)
    )

    assert decision.action == expected
    assert decision.allowed is (expected == "ALLOW")


def test_risk_uses_most_restrictive_signal(engine: PolicyEngine) -> None:
    decision = engine.evaluate_risk(
        make_risk(score=1, severity="LOW", recommendation="BLOCK")
    )

    assert decision.action == "BLOCK"
    assert decision.allowed is False


def test_fail_closed_risk_assessment_is_blocked(engine: PolicyEngine) -> None:
    decision = engine.evaluate_risk(
        make_risk(
            score=100,
            severity="CRITICAL",
            recommendation="BLOCK",
            status="fail_closed",
        )
    )

    assert decision.action == "BLOCK"
    assert decision.allowed is False


def test_missing_policy_fails_closed(local_policy_path: Path) -> None:
    engine = PolicyEngine(local_policy_path)

    assert engine.is_available is False
    decision = engine.check_tool("calculator")
    assert decision.action == "BLOCK"
    assert decision.policy_status == "unavailable"
    assert engine.check_action("calculate").action == "BLOCK"


def test_policy_availability_is_exposed_read_only(engine: PolicyEngine) -> None:
    assert engine.is_available is True
    assert engine.check_tool("calculator").policy_status == "available"


def test_legacy_security_decision_policy_status_remains_accepted() -> None:
    decision = SecurityDecision(
        allowed=False, action="REVIEW", reason="Legacy fixture.",
        policy_status="not_implemented",
    )
    defaulted = SecurityDecision(allowed=False, action="REVIEW", reason="Default fixture.")

    assert decision.policy_status == "not_implemented"
    assert defaulted.policy_status == "not_implemented"


@pytest.mark.parametrize(
    "content",
    ["tools: [calculator", "tools: {}\ndata: {}\nactions: {}\nrisk: {}"],
)
def test_malformed_or_invalid_policy_fails_closed(
    local_policy_path: Path, content: str
) -> None:
    local_policy_path.write_text(content, encoding="utf-8")
    engine = PolicyEngine(local_policy_path)

    assert engine.check_tool("calculator").action == "BLOCK"
    assert engine.check_action("calculate").action == "BLOCK"
    assert engine.check_data(
        DataClassification(data_type="public", destination="internal")
    ).action == "BLOCK"


def test_invalid_policy_rule_fails_closed(local_policy_path: Path) -> None:
    local_policy_path.write_text(
        """
tools:
  allowed: [calculator]
  denied: [calculator]
data:
  types: [public]
  destinations: [internal]
  rules: []
actions:
  rules: []
risk:
  review_threshold: 26
  block_threshold: 76
""",
        encoding="utf-8",
    )

    assert PolicyEngine(local_policy_path).check_tool("calculator").action == "BLOCK"


def test_repeated_evaluation_is_deterministic(engine: PolicyEngine) -> None:
    first = engine.check_data(
        DataClassification(data_type="internal", destination="external")
    )
    second = engine.check_data(
        DataClassification(data_type="internal", destination="external")
    )

    assert first == second
