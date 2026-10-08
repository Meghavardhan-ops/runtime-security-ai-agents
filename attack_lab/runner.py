"""Run local Attack Lab scenarios through the check-only SecurityService."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError

from backend.core.security_service import SecurityService
from backend.detector.models import (
    DetectionCategory,
    DetectionSeverity,
    RecommendedAction,
)
from backend.gateway.input_gateway import SecurityInputRequest, SourceType

_SCENARIO_DIRECTORY = Path(__file__).resolve().parent / "scenarios"
_SAFE_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SEVERITY_RANK: dict[DetectionSeverity, int] = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

ScenarioIdentifier = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$"),
]
PipelineSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]


class _ScenarioExpectation(BaseModel):
    """Validated expected detector labels; arbitrary fields are ignored."""

    model_config = ConfigDict(extra="ignore", strict=True)

    category: DetectionCategory
    minimum_severity: DetectionSeverity
    recommended_action: RecommendedAction


class _Scenario(BaseModel):
    """Only the scenario fields needed for safe analysis are retained."""

    model_config = ConfigDict(extra="ignore", strict=True)

    name: ScenarioIdentifier
    source_type: SourceType
    input: str
    expected: _ScenarioExpectation


class AttackLabResult(BaseModel):
    """Metadata-only outcome for one scenario, with detector and risk separate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_name: ScenarioIdentifier
    scenario_file: str
    source_type: SourceType
    expected_category: DetectionCategory
    actual_category: DetectionCategory | None
    expected_minimum_severity: DetectionSeverity
    actual_severity: DetectionSeverity | None
    expected_recommended_action: RecommendedAction
    actual_recommended_action: RecommendedAction | None
    detection_passed: bool
    pipeline_risk_score: int | None
    pipeline_severity: PipelineSeverity
    pipeline_action: RecommendedAction
    overall_passed: bool


class AttackLabReport(BaseModel):
    """Deterministically ordered summary of the detector scenario checks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    total_scenarios: int
    passed: int
    failed: int
    results: list[AttackLabResult]


def _load_scenario(path: Path) -> _Scenario:
    """Load only validated scenario metadata without echoing content on errors."""
    if not _SAFE_IDENTIFIER.fullmatch(path.stem):
        raise ValueError("Attack Lab scenario filename must be a safe identifier")

    try:
        raw_scenario = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("Unable to load an Attack Lab scenario file") from None

    try:
        return _Scenario.model_validate(raw_scenario)
    except ValidationError:
        # Pydantic validation details can include input values; do not echo them.
        raise ValueError(
            f"Invalid required metadata in Attack Lab scenario '{path.name}'"
        ) from None


def _result_for(
    path: Path, scenario: _Scenario, service: SecurityService
) -> AttackLabResult:
    """Run one input strictly as untrusted text through the existing service."""
    request = SecurityInputRequest(
        source_type=scenario.source_type,
        source_name=f"attack-lab-{path.stem}.txt",
        content=scenario.input,
        metadata={},
    )
    analysis = service.analyze(request)
    detection = analysis.detection_result

    actual_category = detection.category if detection is not None else None
    actual_severity = detection.severity if detection is not None else None
    actual_action = detection.recommended_action if detection is not None else None
    detection_passed = bool(
        detection is not None
        and actual_category == scenario.expected.category
        and actual_severity is not None
        and _SEVERITY_RANK[actual_severity]
        >= _SEVERITY_RANK[scenario.expected.minimum_severity]
        and actual_action == scenario.expected.recommended_action
    )

    # Scenario expectations describe detector behavior. Pipeline risk remains
    # separately visible because unknown ThreatAssessment.threat fails closed.
    return AttackLabResult(
        scenario_name=scenario.name,
        scenario_file=path.name,
        source_type=scenario.source_type,
        expected_category=scenario.expected.category,
        actual_category=actual_category,
        expected_minimum_severity=scenario.expected.minimum_severity,
        actual_severity=actual_severity,
        expected_recommended_action=scenario.expected.recommended_action,
        actual_recommended_action=actual_action,
        detection_passed=detection_passed,
        pipeline_risk_score=analysis.risk_score,
        pipeline_severity=analysis.severity,
        pipeline_action=analysis.action,
        overall_passed=detection_passed,
    )


def run_attack_lab() -> AttackLabReport:
    """Run every bundled JSON scenario in sorted filename order.

    The returned report contains only validated identifiers and security
    metadata. Scenario inputs, generated request IDs, timestamps, and tool
    arguments are never copied into report fields.
    """
    if not _SCENARIO_DIRECTORY.is_dir():
        raise FileNotFoundError("Attack Lab scenarios directory is missing")

    scenario_files = sorted(_SCENARIO_DIRECTORY.glob("*.json"), key=lambda p: p.name)
    service = SecurityService()
    results = [
        _result_for(path, _load_scenario(path), service) for path in scenario_files
    ]
    passed = sum(result.overall_passed for result in results)
    total = len(results)
    return AttackLabReport(
        total_scenarios=total,
        passed=passed,
        failed=total - passed,
        results=results,
    )
