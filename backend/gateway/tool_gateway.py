"""Check-only interface for a future controlled tool execution gateway."""

from typing import Any

from backend.policy.policy_engine import PolicyEngine, SecurityDecision


class ToolGateway:
    """Evaluate tool requests without running the requested tool."""

    def __init__(self, policy_engine: PolicyEngine) -> None:
        self._policy_engine = policy_engine

    def check(self, tool_name: str, arguments: dict[str, Any]) -> SecurityDecision:
        """Return an authorization decision; arguments are never executed."""
        del arguments
        return self._policy_engine.check_tool(tool_name)
