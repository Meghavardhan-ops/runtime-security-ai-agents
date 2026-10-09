"""Demonstration-only local permissions for synthetic AgentShield identities."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

AgentId = Literal["agent-research", "agent-analyst"]
DataClassificationLabel = Literal[
    "public", "internal", "confidential", "restricted"
]


class AgentPermissionProfile(BaseModel):
    """Synthetic local permission profile, not an authenticated identity."""

    model_config = ConfigDict(frozen=True)

    agent_id: AgentId
    display_name: str
    allowed_tools: tuple[str, ...]
    allowed_data_classifications: tuple[DataClassificationLabel, ...]
    identity_verification: Literal["demonstration_only"] = "demonstration_only"


class AgentPermissionRegistry:
    """Read-only registry of local synthetic agents; unknown IDs are denied."""

    _profiles = (
        AgentPermissionProfile(
            agent_id="agent-research",
            display_name="Research Agent",
            allowed_tools=("search",),
            allowed_data_classifications=("public",),
        ),
        AgentPermissionProfile(
            agent_id="agent-analyst",
            display_name="Analyst Agent",
            allowed_tools=("calculator", "search"),
            allowed_data_classifications=("public", "internal"),
        ),
    )

    def get(self, agent_id: object) -> AgentPermissionProfile | None:
        """Resolve only an exact registered synthetic ID."""
        if not isinstance(agent_id, str):
            return None
        return next((item for item in self._profiles if item.agent_id == agent_id), None)

    def list_profiles(self) -> tuple[AgentPermissionProfile, ...]:
        return self._profiles
