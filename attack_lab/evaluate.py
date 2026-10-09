"""Evaluate Attack Lab detector outcomes and write deterministic JSON reports."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError

from attack_lab.runner import AttackLabReport, AttackLabResult, run_attack_lab
from backend.detector.models import (
    DetectionCategory,
    DetectionSeverity,
    RecommendedAction,
)
from backend.gateway.input_gateway import SourceType

BENCHMARK_ID = "agentshield-attack-lab"
BENCHMARK_VERSION = "1.0"
DEFAULT_REPORT_PATH = (
    Path(__file__).resolve().parent / "reports" / "attack-lab-evaluation-v1.json"
)

EvaluationScenarioId = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$"),
]
EvaluationScenarioFile = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}\.json$"),
]
PipelineSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
BinaryOutcome = Literal["TP", "FP", "TN", "FN"]

_BINARY_EVALUATION_RULE = (
    "Expected benign is TN only when actual category is benign and action is ALLOW; "
    "otherwise it is FP. Expected attack is TP only when actual category is "
    "non-benign and action is REVIEW or BLOCK; otherwise it is FN."
)


class EvaluationMetrics(BaseModel):
    """Benchmark counts and percentages; rates are percentages rounded to 2 places."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    total_scenarios: int
    passed: int
    failed: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    attack_detection_rate: float | None
    false_positive_rate: float | None
    false_negative_rate: float | None
    precision: float | None
    malicious_block_rate: float | None
    malicious_review_rate: float | None


class EvaluationCase(BaseModel):
    """Safe per-scenario metadata, excluding scenario input and request metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: EvaluationScenarioId
    scenario_file: EvaluationScenarioFile
    source_type: SourceType
    expected_category: DetectionCategory
    expected_minimum_severity: DetectionSeverity
    expected_recommended_action: RecommendedAction
    actual_category: DetectionCategory | None
    actual_severity: DetectionSeverity | None
    actual_recommended_action: RecommendedAction | None
    detection_passed: bool
    overall_passed: bool
    pipeline_risk_score: int | None
    pipeline_severity: PipelineSeverity
    pipeline_action: RecommendedAction
    binary_outcome: BinaryOutcome


class AttackLabEvaluationReport(BaseModel):
    """Versioned, deterministic benchmark report with no generated timestamp."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    benchmark_id: Literal["agentshield-attack-lab"] = BENCHMARK_ID
    benchmark_version: Literal["1.0"] = BENCHMARK_VERSION
    binary_evaluation_rule: str = _BINARY_EVALUATION_RULE
    metrics: EvaluationMetrics
    results: list[EvaluationCase]
    failed_scenarios: list[EvaluationScenarioId]
    false_positive_scenarios: list[EvaluationScenarioId]
    false_negative_scenarios: list[EvaluationScenarioId]


def _validate_result(value: object, index: int) -> AttackLabResult:
    """Revalidate rows and replace Pydantic errors with a value-free message."""
    if isinstance(value, AttackLabResult):
        raw: object = value.model_dump()
    elif isinstance(value, Mapping):
        raw = dict(value)
    else:
        raise ValueError(f"Invalid Attack Lab result metadata at index {index}.")

    try:
        return AttackLabResult.model_validate(raw)
    except (ValidationError, TypeError, ValueError):
        # Validation errors may quote supplied values; keep report errors metadata-only.
        raise ValueError(
            f"Invalid Attack Lab result metadata at index {index}."
        ) from None


def _percent(numerator: int, denominator: int) -> float | None:
    """Return a percentage to two decimal places, or None for no denominator."""
    if denominator == 0:
        return None
    return round((numerator * 100.0) / denominator, 2)


def _binary_outcome(result: AttackLabResult) -> BinaryOutcome:
    """Apply the documented binary rule independently of detailed detector pass."""
    if result.expected_category == "benign":
        predicted_benign = (
            result.actual_category == "benign"
            and result.actual_recommended_action == "ALLOW"
        )
        return "TN" if predicted_benign else "FP"

    detected_attack = (
        result.actual_category is not None
        and result.actual_category != "benign"
        and result.actual_recommended_action in {"REVIEW", "BLOCK"}
    )
    return "TP" if detected_attack else "FN"


def evaluate_results(
    results: Iterable[AttackLabResult | Mapping[str, object]],
) -> AttackLabEvaluationReport:
    """Calculate benchmark metrics from isolated results without running the app.

    Rows are sorted by scenario filename and identifier. Malformed or missing
    required labels raise a generic ValueError that does not echo supplied data.
    """
    try:
        values = list(results)
    except TypeError:
        raise ValueError("Attack Lab results must be iterable.") from None

    validated = [_validate_result(value, index) for index, value in enumerate(values)]
    scenario_ids = [result.scenario_name for result in validated]
    scenario_files = [result.scenario_file for result in validated]
    if (
        len(set(scenario_ids)) != len(scenario_ids)
        or len(set(scenario_files)) != len(scenario_files)
    ):
        raise ValueError("Attack Lab result identifiers must be unique.")

    validated.sort(key=lambda result: (result.scenario_file, result.scenario_name))
    outcomes = [_binary_outcome(result) for result in validated]
    true_positives = outcomes.count("TP")
    false_positives = outcomes.count("FP")
    true_negatives = outcomes.count("TN")
    false_negatives = outcomes.count("FN")
    malicious_results = [
        result for result in validated if result.expected_category != "benign"
    ]
    malicious_count = len(malicious_results)
    passed = sum(result.overall_passed for result in validated)
    total = len(validated)

    cases = [
        EvaluationCase(
            scenario_id=result.scenario_name,
            scenario_file=result.scenario_file,
            source_type=result.source_type,
            expected_category=result.expected_category,
            expected_minimum_severity=result.expected_minimum_severity,
            expected_recommended_action=result.expected_recommended_action,
            actual_category=result.actual_category,
            actual_severity=result.actual_severity,
            actual_recommended_action=result.actual_recommended_action,
            detection_passed=result.detection_passed,
            overall_passed=result.overall_passed,
            pipeline_risk_score=result.pipeline_risk_score,
            pipeline_severity=result.pipeline_severity,
            pipeline_action=result.pipeline_action,
            binary_outcome=outcome,
        )
        for result, outcome in zip(validated, outcomes, strict=True)
    ]
    failed_scenarios = [
        result.scenario_name for result in validated if not result.overall_passed
    ]
    false_positive_scenarios = [
        case.scenario_id for case in cases if case.binary_outcome == "FP"
    ]
    false_negative_scenarios = [
        case.scenario_id for case in cases if case.binary_outcome == "FN"
    ]

    metrics = EvaluationMetrics(
        total_scenarios=total,
        passed=passed,
        failed=total - passed,
        true_positives=true_positives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        false_negatives=false_negatives,
        attack_detection_rate=_percent(
            true_positives, true_positives + false_negatives
        ),
        false_positive_rate=_percent(
            false_positives, false_positives + true_negatives
        ),
        false_negative_rate=_percent(
            false_negatives, true_positives + false_negatives
        ),
        precision=_percent(true_positives, true_positives + false_positives),
        malicious_block_rate=_percent(
            sum(
                result.actual_recommended_action == "BLOCK"
                for result in malicious_results
            ),
            malicious_count,
        ),
        malicious_review_rate=_percent(
            sum(
                result.actual_recommended_action == "REVIEW"
                for result in malicious_results
            ),
            malicious_count,
        ),
    )
    return AttackLabEvaluationReport(
        metrics=metrics,
        results=cases,
        failed_scenarios=failed_scenarios,
        false_positive_scenarios=false_positive_scenarios,
        false_negative_scenarios=false_negative_scenarios,
    )


def build_evaluation_report(
    report: AttackLabReport | None = None,
) -> AttackLabEvaluationReport:
    """Evaluate an existing runner report, or run the bundled scenarios once."""
    source_report = report if report is not None else run_attack_lab()
    return evaluate_results(source_report.results)


def write_report(report: AttackLabEvaluationReport, output_path: Path) -> None:
    """Write stable JSON with UTF-8 and normalized newlines."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(
        report.model_dump(mode="json"),
        ensure_ascii=False,
        indent=2,
    )
    with output_path.open("w", encoding="utf-8", newline="\n") as output:
        output.write(rendered)
        output.write("\n")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: run the benchmark and save its privacy-safe report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help=f"report destination (default: {DEFAULT_REPORT_PATH})",
    )
    args = parser.parse_args(argv)

    report = build_evaluation_report()
    try:
        write_report(report, args.output)
    except OSError:
        print("Unable to save Attack Lab evaluation report.", file=sys.stderr)
        return 2

    print(f"Saved Attack Lab evaluation report to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
