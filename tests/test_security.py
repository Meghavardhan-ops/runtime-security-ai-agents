"""Tests for the check-only Security API and its unimplemented boundaries."""

import logging

import pytest
from fastapi.testclient import TestClient

from backend.api.security import router
from backend.main import app

client = TestClient(app)
SECURITY_URL = "/api/v1/security"


def gateway_payload() -> dict[str, object]:
    return {
        "source_type": "text",
        "source_name": "task.txt",
        "content": "Summarize the quarterly report.",
        "metadata": {"origin": "test"},
    }


def test_security_router_imports() -> None:
    assert router.prefix == SECURITY_URL


def test_security_status_is_truthful() -> None:
    response = client.get(f"{SECURITY_URL}/status")

    assert response.status_code == 200
    assert response.json() == {
        "security_router": "active",
        "input_gateway": "active",
        "threat_detector": "not_implemented",
        "risk_engine": "not_implemented",
        "policy_engine": "not_implemented",
        "data_classifier": "not_implemented",
        "tool_gateway": "not_implemented",
        "audit_logging": "active",
    }


def test_analyze_normalizes_untrusted_input_and_is_explicitly_unimplemented() -> None:
    response = client.post(f"{SECURITY_URL}/analyze", json=gateway_payload())

    assert response.status_code == 200
    result = response.json()
    assert result["input_id"]
    assert result["analysis_status"] == "not_implemented"
    assert result["risk_score"] is None
    assert result["severity"] == "UNKNOWN"
    assert result["threat"] == "not_assessed"
    assert result["action"] == "REVIEW"
    assert result["indicators"] == []


def test_analyze_revalidates_a_security_input_response() -> None:
    input_response = client.post("/api/v1/inputs", json=gateway_payload())
    assert input_response.status_code == 201

    response = client.post(f"{SECURITY_URL}/analyze", json=input_response.json())

    assert response.status_code == 200
    assert response.json()["input_id"] != input_response.json()["id"]


def test_analyze_rejects_invalid_input() -> None:
    response = client.post(
        f"{SECURITY_URL}/analyze",
        json={**gateway_payload(), "content": "  "},
    )

    assert response.status_code == 422


def test_analyze_response_fields_are_deterministic() -> None:
    first = client.post(f"{SECURITY_URL}/analyze", json=gateway_payload()).json()
    second = client.post(f"{SECURITY_URL}/analyze", json=gateway_payload()).json()

    stable_fields = (
        "analysis_status",
        "risk_score",
        "severity",
        "threat",
        "action",
        "indicators",
        "reason",
    )
    assert all(first[field] == second[field] for field in stable_fields)
    assert first["input_id"] != second["input_id"]


def test_analyze_rejects_missing_fields() -> None:
    response = client.post(f"{SECURITY_URL}/analyze", json={"source_type": "text"})

    assert response.status_code == 422


def test_check_tool_fails_closed_and_never_echoes_arguments() -> None:
    sensitive_argument = "TOOL-ARGUMENT-SHOULD-NOT-APPEAR"
    response = client.post(
        f"{SECURITY_URL}/check-tool",
        json={"tool_name": "file_read", "arguments": {"path": sensitive_argument}},
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert response.json()["tool_name"] == "file_read"
    assert response.json()["action"] == "BLOCK"
    assert response.json()["policy_status"] == "not_implemented"
    assert sensitive_argument not in response.text


def test_check_data_blocks_confidential_external_transfer() -> None:
    response = client.post(
        f"{SECURITY_URL}/check-data",
        json={"data_type": "confidential", "destination": "external"},
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert response.json()["action"] == "BLOCK"
    assert "requires policy evaluation" in response.json()["reason"]


def test_check_action_denies_without_performing_action() -> None:
    target = "external@example.com"
    response = client.post(
        f"{SECURITY_URL}/check-action",
        json={"action": "send_email", "target": target},
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert response.json()["action"] == "BLOCK"
    assert target not in response.text


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("check-tool", {}),
        ("check-tool", {"tool_name": "  "}),
        ("check-tool", {"tool_name": "file_read", "unexpected": True}),
        ("check-data", {"data_type": "confidential"}),
        ("check-action", {"action": "send_email", "target": "  "}),
    ],
)
def test_check_endpoints_validate_requests(path: str, payload: dict[str, object]) -> None:
    response = client.post(f"{SECURITY_URL}/{path}", json=payload)

    assert response.status_code == 422


def test_check_responses_are_deterministic() -> None:
    request = {"tool_name": "file_read", "arguments": {"path": "report.txt"}}

    first = client.post(f"{SECURITY_URL}/check-tool", json=request)
    second = client.post(f"{SECURITY_URL}/check-tool", json=request)

    assert first.json() == second.json()


def test_sensitive_security_request_values_are_not_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "PRIVATE-TARGET-AND-ARGUMENT"
    with caplog.at_level(logging.INFO, logger="backend.monitor.audit_logger"):
        client.post(
            f"{SECURITY_URL}/check-tool",
            json={"tool_name": "file_read", "arguments": {"token": secret}},
        )
        client.post(
            f"{SECURITY_URL}/check-action",
            json={"action": "send_email", "target": secret},
        )

    assert secret not in caplog.text


def test_tool_gateway_has_no_execution_method() -> None:
    from backend.gateway.tool_gateway import ToolGateway
    from backend.policy.policy_engine import PolicyEngine

    tool_gateway = ToolGateway(PolicyEngine())

    assert not hasattr(tool_gateway, "execute")
    assert not hasattr(tool_gateway, "execute_tool")
