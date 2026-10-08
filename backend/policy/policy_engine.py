"""Fail-closed decision interfaces for a future policy engine."""

from typing import Literal

from pydantic import BaseModel

from backend.policy.data_classifier import DataClassification


class SecurityDecision(BaseModel):
    """Structured decision returned by check-only security interfaces."""

    allowed: bool
    action: Literal["ALLOW", "BLOCK", "REVIEW"]
    reason: str
    policy_status: Literal["not_implemented"] = "not_implemented"


class PolicyEngine:
    """Fail closed until explicit policy evaluation is implemented."""

    def check_tool(self, tool_name: str) -> SecurityDecision:
        """Deny tool authorization because no policy rules are active."""
        del tool_name
        return SecurityDecision(
            allowed=False,
            action="BLOCK",
            reason="Policy engine is not implemented; tool access is denied by default.",
        )

    def check_data(self, classification: DataClassification) -> SecurityDecision:
        """Deny data movement because supplied labels are not verified by policy."""
        is_confidential_external = (
            classification.data_type.casefold() == "confidential"
            and classification.destination.casefold() == "external"
        )
        if is_confidential_external:
            reason = (
                "External transfer of confidential data requires policy evaluation; "
                "the policy engine is not implemented."
            )
        else:
            reason = (
                "Policy engine is not implemented; data movement requires explicit "
                "authorization."
            )
        return SecurityDecision(allowed=False, action="BLOCK", reason=reason)

    def check_action(self, action: str) -> SecurityDecision:
        """Deny action authorization because no policy rules are active."""
        del action
        return SecurityDecision(
            allowed=False,
            action="BLOCK",
            reason="Policy engine is not implemented; actions are denied by default.",
        )
