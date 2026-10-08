"""Deterministic policy checks for tools, data flows, actions, and risk."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from backend.policy.data_classifier import DataClassification
from backend.policy.risk_engine import RiskAssessment

DecisionAction = Literal["ALLOW", "REVIEW", "BLOCK"]
PolicyStatus = Literal["not_implemented"]


class SecurityDecision(BaseModel):
    """Structured, check-only policy decision compatible with the Security API."""

    model_config = ConfigDict(frozen=True)

    allowed: bool
    action: DecisionAction
    reason: str
    # Retained for compatibility with the existing Security Router response.
    policy_status: PolicyStatus = "not_implemented"


class DataRule(BaseModel):
    """Decision for one normalized data type and destination pair."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    data_type: str = Field(min_length=1)
    destination: str = Field(min_length=1)
    action: DecisionAction
    reason: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def normalize_labels(self) -> DataRule:
        data_type = self.data_type.strip().casefold()
        destination = self.destination.strip().casefold()
        if not data_type or not destination:
            raise ValueError("data rule labels must not be empty")
        object.__setattr__(self, "data_type", data_type)
        object.__setattr__(self, "destination", destination)
        return self


class ActionRule(BaseModel):
    """Decision for one normalized action name."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: str = Field(min_length=1)
    decision: DecisionAction
    reason: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def normalize_action(self) -> ActionRule:
        action = self.action.strip().casefold()
        if not action:
            raise ValueError("action rule name must not be empty")
        object.__setattr__(self, "action", action)
        return self


class ToolRules(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: tuple[str, ...] = ()
    denied: tuple[str, ...] = ()

    @model_validator(mode="after")
    def normalize_and_validate(self) -> ToolRules:
        allowed = tuple(
            self._normalize_name(name, "allowed tool") for name in self.allowed
        )
        denied = tuple(
            self._normalize_name(name, "denied tool") for name in self.denied
        )
        if len(set(allowed)) != len(allowed) or len(set(denied)) != len(denied):
            raise ValueError("tool names must not be duplicated")
        if set(allowed) & set(denied):
            raise ValueError("a tool cannot be both allowed and denied")
        object.__setattr__(self, "allowed", allowed)
        object.__setattr__(self, "denied", denied)
        return self

    @staticmethod
    def _normalize_name(value: str, label: str) -> str:
        normalized = value.strip().casefold()
        if not normalized:
            raise ValueError(f"{label} names must not be empty")
        return normalized


class DataRules(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    types: tuple[str, ...]
    destinations: tuple[str, ...]
    rules: tuple[DataRule, ...] = ()

    @model_validator(mode="after")
    def validate_rules(self) -> DataRules:
        types = tuple(self._normalize_label(value) for value in self.types)
        destinations = tuple(self._normalize_label(value) for value in self.destinations)
        if not types or not destinations:
            raise ValueError("data types and destinations must not be empty")
        if len(set(types)) != len(types) or len(set(destinations)) != len(destinations):
            raise ValueError("data types and destinations must not be duplicated")

        seen: set[tuple[str, str]] = set()
        for rule in self.rules:
            key = (rule.data_type, rule.destination)
            if key in seen:
                raise ValueError("data rule combinations must not be duplicated")
            if rule.data_type not in types or rule.destination not in destinations:
                raise ValueError("data rules must use declared types and destinations")
            if key == ("confidential", "external") and rule.action == "ALLOW":
                raise ValueError("confidential data cannot be allowed to external destinations")
            seen.add(key)

        object.__setattr__(self, "types", types)
        object.__setattr__(self, "destinations", destinations)
        return self

    @staticmethod
    def _normalize_label(value: str) -> str:
        normalized = value.strip().casefold()
        if not normalized:
            raise ValueError("data labels must not be empty")
        return normalized


class ActionRules(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rules: tuple[ActionRule, ...] = ()

    @model_validator(mode="after")
    def reject_duplicate_actions(self) -> ActionRules:
        names = [rule.action for rule in self.rules]
        if len(set(names)) != len(names):
            raise ValueError("action rules must not be duplicated")
        return self


class RiskRules(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    review_threshold: int = Field(ge=0, le=100, strict=True)
    block_threshold: int = Field(ge=0, le=100, strict=True)

    @model_validator(mode="after")
    def thresholds_are_ordered(self) -> RiskRules:
        if self.review_threshold >= self.block_threshold:
            raise ValueError("review_threshold must be below block_threshold")
        return self


class PolicyConfig(BaseModel):
    """Fully validated policy data loaded from the local YAML file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tools: ToolRules
    data: DataRules
    actions: ActionRules
    risk: RiskRules


class PolicyEngine:
    """Load and evaluate local policy rules without executing requested work."""

    _RISK_RESTRICTION: dict[str, int] = {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}
    _SEVERITY_ACTION: dict[str, DecisionAction] = {
        "LOW": "ALLOW",
        "MEDIUM": "REVIEW",
        "HIGH": "REVIEW",
        "CRITICAL": "BLOCK",
    }
    _RECOMMENDED_ACTION: dict[str, DecisionAction] = {
        "ALLOW": "ALLOW",
        "REVIEW": "REVIEW",
        "BLOCK": "BLOCK",
    }

    def __init__(self, policy_path: str | Path | None = None) -> None:
        """Load one validated YAML policy; an unavailable policy denies all checks."""
        self.policy_path = (
            Path(policy_path)
            if policy_path is not None
            else Path(__file__).resolve().parents[2] / "policies" / "default.yaml"
        )
        self._policy = self._load_policy(self.policy_path)

    @staticmethod
    def _load_policy(path: Path) -> PolicyConfig | None:
        try:
            raw_policy = yaml.safe_load(path.read_text(encoding="utf-8"))
            return PolicyConfig.model_validate(raw_policy)
        except (
            OSError,
            UnicodeError,
            yaml.YAMLError,
            ValidationError,
            TypeError,
            ValueError,
            RecursionError,
        ):
            return None

    @staticmethod
    def _normalize_name(value: object) -> str | None:
        if not isinstance(value, str):
            return None
        normalized = value.strip().casefold()
        return normalized or None

    @staticmethod
    def _decision(action: DecisionAction, reason: str) -> SecurityDecision:
        return SecurityDecision(
            allowed=action == "ALLOW",
            action=action,
            reason=reason,
        )

    def check_tool(self, tool_name: str) -> SecurityDecision:
        """Allow only an explicitly listed tool; unknown inputs deny by default."""
        name = self._normalize_name(tool_name)
        if self._policy is None:
            return self._decision(
                "BLOCK", "Policy configuration is unavailable; tool denied."
            )
        if name is None:
            return self._decision("BLOCK", "Tool name is empty or invalid; tool denied.")
        if name in self._policy.tools.denied:
            return self._decision("BLOCK", f"Tool '{name}' is explicitly denied by policy.")
        if name in self._policy.tools.allowed:
            return self._decision("ALLOW", f"Tool '{name}' is explicitly allowed by policy.")
        return self._decision(
            "BLOCK", f"Tool '{name}' is not listed in policy; denied by default."
        )

    def check_data(self, classification: DataClassification) -> SecurityDecision:
        """Evaluate caller-supplied classification labels without moving data."""
        if self._policy is None:
            return self._decision(
                "BLOCK", "Policy configuration is unavailable; data flow denied."
            )
        if not isinstance(classification, DataClassification):
            return self._decision("BLOCK", "Data classification is invalid; data flow denied.")

        data_type = self._normalize_name(classification.data_type)
        destination = self._normalize_name(classification.destination)
        if data_type is None or data_type not in self._policy.data.types:
            return self._decision("BLOCK", "Unknown or empty data type; data flow denied.")
        if destination is None or destination not in self._policy.data.destinations:
            return self._decision("BLOCK", "Unknown or empty destination; data flow denied.")

        if data_type == "confidential" and destination == "external":
            return self._decision(
                "BLOCK",
                "External transfer of confidential data requires policy evaluation and is blocked.",
            )

        rule = next(
            (
                candidate
                for candidate in self._policy.data.rules
                if candidate.data_type == data_type
                and candidate.destination == destination
            ),
            None,
        )
        if rule is None:
            return self._decision(
                "BLOCK",
                f"No data rule exists for '{data_type}' to '{destination}'; denied by default.",
            )
        reason = rule.reason or (
            f"Data flow '{data_type}' to '{destination}' is {rule.action} by policy."
        )
        return self._decision(rule.action, reason)

    def check_action(self, action: str) -> SecurityDecision:
        """Evaluate a named action without carrying it out."""
        name = self._normalize_name(action)
        if self._policy is None:
            return self._decision(
                "BLOCK", "Policy configuration is unavailable; action denied."
            )
        if name is None:
            return self._decision("BLOCK", "Action name is empty or invalid; action denied.")

        rule = next(
            (
                candidate
                for candidate in self._policy.actions.rules
                if candidate.action == name
            ),
            None,
        )
        if rule is None:
            return self._decision(
                "BLOCK", f"Action '{name}' is not listed in policy; denied by default."
            )
        reason = rule.reason or f"Action '{name}' is {rule.decision} by policy."
        return self._decision(rule.decision, reason)

    def evaluate_risk(self, risk_assessment: RiskAssessment) -> SecurityDecision:
        """Combine score, severity, and recommendation using the strictest result."""
        if self._policy is None:
            return self._decision(
                "BLOCK", "Policy configuration is unavailable; risk evaluation denied."
            )
        if not isinstance(risk_assessment, RiskAssessment):
            return self._decision("BLOCK", "Risk assessment is invalid; fail-closed decision.")
        if risk_assessment.status != "scored":
            return self._decision("BLOCK", "Risk assessment is fail-closed; operation blocked.")

        score = risk_assessment.risk_score
        if score >= self._policy.risk.block_threshold:
            score_action: DecisionAction = "BLOCK"
        elif score >= self._policy.risk.review_threshold:
            score_action = "REVIEW"
        else:
            score_action = "ALLOW"

        actions = {
            "score threshold": score_action,
            "severity": self._SEVERITY_ACTION[risk_assessment.severity],
            "risk recommendation": self._RECOMMENDED_ACTION[
                risk_assessment.recommended_action
            ],
        }
        strictest = max(actions.values(), key=self._RISK_RESTRICTION.__getitem__)
        contributing_signals = [
            f"{label}={action}"
            for label, action in actions.items()
            if action == strictest
        ]
        detail = "; ".join(contributing_signals)
        reason = (
            f"Risk assessment score={score}, severity={risk_assessment.severity}; "
            f"strictest result is {strictest} from {detail}."
        )
        if risk_assessment.reasons:
            reason += " Assessment: " + " ".join(risk_assessment.reasons)
        return self._decision(strictest, reason)
