"""Tests for the deterministic, metadata-only Attack Lab runner."""

import json
import re
from pathlib import Path
import tempfile
from types import SimpleNamespace

import pytest

import attack_lab.runner as attack_lab
from backend.detector.models import DetectionResult

_EXPECTED = {
    "category": "prompt_injection",
    "minimum_severity": "HIGH",
    "recommended_action": "BLOCK",
}
_RAW_INPUT = "PRIVATE-SCENARIO-INPUT-DO-NOT-REPORT"


@pytest.fixture
def scenario_dir(monkeypatch):
    with tempfile.TemporaryDirectory(
        prefix=".attack-lab-tests-", dir=Path(__file__).parent
    ) as directory:
        path = Path(directory)
        monkeypatch.setattr(attack_lab, "_SCENARIO_DIRECTORY", path)
        yield path


def _scenario(**overrides: object) -> dict[str, object]:
    scenario: dict[str, object] = {
        "name": "scenario_case",
        "source_type": "text",
        "input": _RAW_INPUT,
        "expected": dict(_EXPECTED),
    }
    scenario.update(overrides)
    return scenario


class _StubService:
    def __init__(self, detection: DetectionResult) -> None:
        self.detection = detection
        self.request = None

    def analyze(self, request: object) -> SimpleNamespace:
        self.request = request
        return SimpleNamespace(
            detection_result=self.detection,
            risk_score=100,
            severity="CRITICAL",
            action="BLOCK",
        )


def test_runner_discovers_all_scenarios_in_filename_order_and_is_deterministic() -> None:
    report = attack_lab.run_attack_lab()
    second_report = attack_lab.run_attack_lab()
    expected_files = sorted(
        path.name for path in attack_lab._SCENARIO_DIRECTORY.glob("*.json")
    )

    assert report.total_scenarios == 9
    assert report.passed + report.failed == 9
    assert [result.scenario_file for result in report.results] == expected_files
    assert report.model_dump(mode="json") == second_report.model_dump(mode="json")

    serialized = report.model_dump_json()
    scenario_inputs = [
        json.loads(path.read_text(encoding="utf-8"))["input"]
        for path in attack_lab._SCENARIO_DIRECTORY.glob("*.json")
    ]
    assert all(raw_input not in serialized for raw_input in scenario_inputs)
    assert not re.search(
        r"\b(?:request_id|input_id|timestamp|received_at)\b", serialized
    )
    assert not re.search(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        serialized,
        re.IGNORECASE,
    )

    assert set(report.model_dump().keys()) == {
        "total_scenarios",
        "passed",
        "failed",
        "results",
    }
    assert set(report.results[0].model_dump().keys()) == {
        "scenario_name",
        "scenario_file",
        "source_type",
        "expected_category",
        "actual_category",
        "expected_minimum_severity",
        "actual_severity",
        "expected_recommended_action",
        "actual_recommended_action",
        "detection_passed",
        "pipeline_risk_score",
        "pipeline_severity",
        "pipeline_action",
        "overall_passed",
    }

    benign = next(result for result in report.results if result.scenario_name == "benign_request")
    assert benign.actual_category == "benign"
    assert benign.actual_severity == "LOW"
    assert benign.actual_recommended_action == "ALLOW"
    assert benign.detection_passed is True
    assert benign.overall_passed is True
    assert benign.pipeline_risk_score == 100
    assert benign.pipeline_severity == "CRITICAL"
    assert benign.pipeline_action == "BLOCK"


@pytest.mark.parametrize(
    ("actual_category", "actual_severity", "actual_action", "expected_pass"),
    [
        ("prompt_injection", "CRITICAL", "BLOCK", True),
        ("data_exfiltration", "CRITICAL", "BLOCK", False),
        ("prompt_injection", "MEDIUM", "BLOCK", False),
        ("prompt_injection", "CRITICAL", "REVIEW", False),
    ],
)
def test_detection_expectations_use_category_minimum_severity_and_exact_action(
    scenario_dir, monkeypatch, actual_category, actual_severity, actual_action, expected_pass
) -> None:
    scenario_path = scenario_dir / "scenario_case.json"
    scenario_path.write_text(json.dumps(_scenario()), encoding="utf-8")
    detection = DetectionResult(
        category=actual_category,
        severity=actual_severity,
        risk_score=80,
        indicators=[],
        recommended_action=actual_action,
    )
    service = _StubService(detection)
    monkeypatch.setattr(attack_lab, "SecurityService", lambda: service)

    report = attack_lab.run_attack_lab()
    result = report.results[0]

    assert result.detection_passed is expected_pass
    assert result.overall_passed is expected_pass
    assert result.pipeline_risk_score == 100
    assert result.pipeline_action == "BLOCK"
    assert service.request.source_type == "text"
    assert service.request.source_name == "attack-lab-scenario_case.txt"
    assert service.request.content == _RAW_INPUT
    assert service.request.metadata == {}
    assert _RAW_INPUT not in report.model_dump_json()


@pytest.mark.parametrize(
    "missing_field",
    [
        "name",
        "source_type",
        "input",
        "expected.category",
        "expected.minimum_severity",
        "expected.recommended_action",
    ],
)
def test_runner_rejects_scenarios_missing_required_fields(
    scenario_dir, missing_field
) -> None:
    scenario = _scenario()
    if missing_field.startswith("expected."):
        scenario["expected"].pop(missing_field.split(".", 1)[1])
    else:
        scenario.pop(missing_field)
    (scenario_dir / "scenario_case.json").write_text(
        json.dumps(scenario), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="Invalid required metadata") as error:
        attack_lab.run_attack_lab()

    assert _RAW_INPUT not in str(error.value)
