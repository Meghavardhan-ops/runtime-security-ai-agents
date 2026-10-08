"""Check-only authorization boundary for agent tool requests."""

from math import isfinite
from typing import Any, Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError

from backend.policy.policy_engine import PolicyEngine, SecurityDecision

ToolName = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)
]


class _ToolRequest(BaseModel):
    """Validated request envelope; argument values remain inert data."""

    model_config = ConfigDict(extra="forbid", strict=True)

    tool_name: ToolName
    arguments: dict[str, Any]


class ToolGateway:
    """Validate and authorize requests without invoking tools or arguments."""

    _MAX_ARGUMENT_DEPTH = 8
    _MAX_ARGUMENT_NODES = 1024
    _MAX_ARGUMENT_BYTES = 64 * 1024

    def __init__(self, policy_engine: PolicyEngine) -> None:
        self._policy_engine = policy_engine

    def check(self, tool_name: str, arguments: dict[str, Any]) -> SecurityDecision:
        """Return ALLOW, REVIEW, or BLOCK; this method never executes a tool."""
        try:
            request = _ToolRequest.model_validate(
                {"tool_name": tool_name, "arguments": arguments}
            )
        except ValidationError:
            return self._block("Invalid tool request; access denied.")

        try:
            if not self._arguments_are_bounded(request.arguments):
                return self._block(
                    "Tool arguments are invalid or exceed limits; access denied."
                )
        except (UnicodeError, OverflowError):
            return self._block(
                "Tool arguments are invalid or exceed limits; access denied."
            )

        try:
            decision = self._policy_engine.check_tool(request.tool_name)
            if not isinstance(decision, SecurityDecision):
                return self._block(
                    "Policy returned an invalid decision; tool access denied."
                )
            if decision.action not in {"ALLOW", "REVIEW", "BLOCK"}:
                return self._block(
                    "Policy returned an invalid decision; tool access denied."
                )
            if type(decision.allowed) is not bool:
                return self._block(
                    "Policy returned an invalid decision; tool access denied."
                )
            if decision.allowed is not (decision.action == "ALLOW"):
                return self._block(
                    "Policy returned an invalid decision; tool access denied."
                )
        except Exception:
            return self._block("Policy evaluation failed; tool access denied.")

        return decision

    @classmethod
    def _arguments_are_bounded(cls, arguments: dict[str, Any]) -> bool:
        """Accept only bounded JSON-like values without copying or transforming them."""
        pending: list[tuple[object, int]] = [(arguments, 0)]
        node_count = 0
        byte_count = 0

        while pending:
            value, depth = pending.pop()
            node_count += 1
            if (
                node_count > cls._MAX_ARGUMENT_NODES
                or depth > cls._MAX_ARGUMENT_DEPTH
            ):
                return False

            if type(value) is dict:
                if len(value) > cls._MAX_ARGUMENT_NODES:
                    return False
                for key, child in value.items():
                    if type(key) is not str:
                        return False
                    if len(key) > cls._MAX_ARGUMENT_BYTES:
                        return False
                    byte_count += len(key.encode("utf-8"))
                    if byte_count > cls._MAX_ARGUMENT_BYTES:
                        return False
                    node_count += 1
                    if node_count > cls._MAX_ARGUMENT_NODES:
                        return False
                    pending.append((child, depth + 1))
            elif type(value) is list:
                if len(value) > cls._MAX_ARGUMENT_NODES:
                    return False
                pending.extend((child, depth + 1) for child in value)
            elif type(value) is str:
                if len(value) > cls._MAX_ARGUMENT_BYTES:
                    return False
                byte_count += len(value.encode("utf-8"))
                if byte_count > cls._MAX_ARGUMENT_BYTES:
                    return False
            elif type(value) is int:
                if value.bit_length() > 128:
                    return False
                byte_count += 16
            elif type(value) is float:
                if not isfinite(value):
                    return False
                byte_count += 16
            elif type(value) is bool or value is None:
                byte_count += 8
            else:
                return False

            if byte_count > cls._MAX_ARGUMENT_BYTES:
                return False

        return True

    @staticmethod
    def _block(reason: str) -> SecurityDecision:
        return SecurityDecision(allowed=False, action="BLOCK", reason=reason)
