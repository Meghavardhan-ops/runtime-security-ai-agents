"""Tests for the isolated, metadata-only Attack Lab evaluation layer."""

import json
from pathlib import Path

import pytest

import attack_lab.evaluate as evaluation
from attack_lab.runner import AttackLabReport, AttackLabResult


def _result(
    scenario_id: str,
    *,
    expected: str,
    actual: str | None,
    action: str | None,
    passed: bool = True,
) -> AttackLabResult:
    return AttackLabResult(
        scenario_name=scenario_id,
        scenario_file=f"{scenario_id}.json",
        source_type="text",
        expected_category=expected,
        actual_category=actual,
        expected_minimum_severity="LOW",
        actual_severity="LOW" if actual is not None else None,
        expected_recommended_action="ALLOW",
        actual_recommended_action=action,
        detection_passed=passed,
        pipeline_risk_score=0,
        pipeline_severity="LOW",
        pipeline_action="ALLOW",
        overall_passed=passed,
    )


@pytest.fixture
def hand_calculated_results() -> list[AttackLabResult]:
    return [
        _result(
            "attack_block",
            expected="prompt_injection",
            actual="prompt_injection",
            action="BLOCK",
        ),
        _result(
            "attack_review",
            expected="data_exfiltration",
            actual="data_exfiltration",
            action="REVIEW",
        ),
        _result(
            "attack_missed",
            expected="credential_theft",
            actual="benign",
            action="ALLOW",
            passed=False,
        ),
        _result(
            "benign_flagged",
            expected="benign",
            actual="suspicious",
            action="REVIEW",
            passed=False,
        ),
        _result("benign_clean", expected="benign", actual="benign", action="ALLOW"),
    ]


def test_counts_and_rates_follow_binary_rule(hand_calculated_results) -> None:
    report = evaluation.evaluate_results(hand_calculated_results)
    metrics = report.metrics

    assert (metrics.total_scenarios, metrics.passed, metrics.failed) == (5, 3, 2)
    assert (
        metrics.true_positives,
        metrics.false_positives,
        metrics.true_negatives,
        metrics.false_negatives,
    ) == (2, 1, 1, 1)
    assert metrics.attack_detection_rate == 66.67
    assert metrics.precision == 66.67
    assert metrics.false_positive_rate == 50.0
    assert metrics.false_negative_rate == 33.33
    assert metrics.malicious_block_rate == 33.33
    assert metrics.malicious_review_rate == 33.33
    assert report.false_positive_scenarios == ["benign_flagged"]
    assert report.false_negative_scenarios == ["attack_missed"]
    assert report.failed_scenarios == ["attack_missed", "benign_flagged"]


def test_benign_suspicion_or_restriction_is_a_false_positive() -> None:
    results = [
        _result(
            "benign_review", expected="benign", actual="benign", action="REVIEW"
        ),
        _result(
            "benign_block", expected="benign", actual="suspicious", action="BLOCK"
        ),
    ]

    report = evaluation.evaluate_results(results)

    assert report.metrics.false_positives == 2
    assert report.metrics.true_negatives == 0
    assert report.false_positive_scenarios == ["benign_block", "benign_review"]


def test_attack_with_benign_or_allowed_result_is_a_false_negative() -> None:
    results = [
        _result(
            "attack_benign", expected="tool_abuse", actual="benign", action="BLOCK"
        ),
        _result(
            "attack_allowed",
            expected="prompt_injection",
            actual="prompt_injection",
            action="ALLOW",
        ),
        _result(
            "attack_unassessed",
            expected="credential_theft",
            actual=None,
            action=None,
        ),
    ]

    report = evaluation.evaluate_results(results)

    assert report.metrics.false_negatives == 3
    assert report.false_negative_scenarios == [
        "attack_allowed",
        "attack_benign",
        "attack_unassessed",
    ]


def test_empty_and_zero_denominator_metrics_are_safe() -> None:
    empty = evaluation.evaluate_results([]).metrics
    assert empty.total_scenarios == empty.passed == empty.failed == 0
    assert empty.true_positives == empty.false_positives == 0
    assert empty.true_negatives == empty.false_negatives == 0
    assert empty.attack_detection_rate is None
    assert empty.false_positive_rate is None
    assert empty.false_negative_rate is None
    assert empty.precision is None
    assert empty.malicious_block_rate is None
    assert empty.malicious_review_rate is None

    benign_only = evaluation.evaluate_results(
        [_result("benign_only", expected="benign", actual="benign", action="ALLOW")]
    ).metrics
    assert benign_only.false_positive_rate == 0.0
    assert benign_only.attack_detection_rate is None
    assert benign_only.false_negative_rate is None
    assert benign_only.precision is None
    assert benign_only.malicious_block_rate is None
    assert benign_only.malicious_review_rate is None


@pytest.mark.parametrize(
    ("mutation", "invalid_label"),
    [
        ("missing", None),
        ("invalid", "PRIVATE-SECRET-CATEGORY"),
    ],
)
def test_invalid_or_missing_labels_fail_without_echoing_values(
    mutation, invalid_label
) -> None:
    row = _result(
        "invalid_label", expected="benign", actual="benign", action="ALLOW"
    ).model_dump()
    if mutation == "missing":
        del row["expected_category"]
    else:
        row["expected_category"] = invalid_label

    with pytest.raises(ValueError) as error:
        evaluation.evaluate_results([row])

    assert "PRIVATE-SECRET-CATEGORY" not in str(error.value)


def test_missing_actual_labels_are_counted_conservatively() -> None:
    report = evaluation.evaluate_results(
        [
            _result(
                "unknown_benign", expected="benign", actual=None, action=None
            ),
            _result(
                "unknown_attack",
                expected="data_exfiltration",
                actual=None,
                action=None,
            ),
        ]
    )

    assert report.metrics.false_positives == 1
    assert report.metrics.false_negatives == 1


def test_report_json_is_private_repeatable_and_scenario_sorted(
    hand_calculated_results, tmp_path: Path
) -> None:
    forward = evaluation.evaluate_results(hand_calculated_results)
    reverse = evaluation.evaluate_results(reversed(hand_calculated_results))
    assert forward.model_dump(mode="json") == reverse.model_dump(mode="json")
    assert [case.scenario_file for case in forward.results] == sorted(
        case.scenario_file for case in forward.results
    )

    output = tmp_path / "nested" / "evaluation.json"
    evaluation.write_report(forward, output)
    first_json = output.read_text(encoding="utf-8")
    evaluation.write_report(reverse, output)
    second_json = output.read_text(encoding="utf-8")

    assert first_json == second_json
    assert "agentshield-attack-lab" in first_json
    assert "benchmark_version" in first_json
    assert "timestamp" not in first_json
    assert "raw_input" not in first_json
    assert "secret" not in first_json.lower()
    assert json.loads(first_json)["metrics"]["true_positives"] == 2


def test_cli_generates_json_from_existing_runner_report(monkeypatch, tmp_path: Path) -> None:
    results = [
        _result(
            "benign_case", expected="benign", actual="benign", action="ALLOW"
        ),
        _result(
            "attack_case",
            expected="prompt_injection",
            actual="prompt_injection",
            action="BLOCK",
        ),
    ]
    runner_report = AttackLabReport(
        total_scenarios=2,
        passed=2,
        failed=0,
        results=results,
    )
    assert set(runner_report.model_dump()) == {
        "total_scenarios",
        "passed",
        "failed",
        "results",
    }
    monkeypatch.setattr(evaluation, "run_attack_lab", lambda: runner_report)
    destination = tmp_path / "evaluation.json"

    assert evaluation.main(["--output", str(destination)]) == 0
    saved = json.loads(destination.read_text(encoding="utf-8"))
    assert saved["metrics"]["true_positives"] == 1
    assert saved["metrics"]["true_negatives"] == 1
    assert len(saved["results"]) == 2


def test_unrecognized_extra_sensitive_fields_are_rejected_without_echoing() -> None:
    sensitive = "RAW-SECRET-DO-NOT-REPORT"
    row = _result(
        "private_case", expected="benign", actual="benign", action="ALLOW"
    ).model_dump()
    row["raw_content"] = sensitive

    with pytest.raises(ValueError) as error:
        evaluation.evaluate_results([row])

    assert sensitive not in str(error.value)
