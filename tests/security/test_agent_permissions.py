"""Integration checks for synthetic agent permission enforcement."""

import logging

import pytest

from backend.api.security import (
    AgentDataContentCheckRequest,
    AgentToolCheckRequest,
    agent_permissions_view,
    check_agent_data_content,
    check_agent_tool,
)
from backend.core.security_service import SecurityService


def test_registered_agent_tool_must_also_pass_policy() -> None:
    response = check_agent_tool(AgentToolCheckRequest(
        agent_id="agent-research", tool_name="search", arguments={"query": "safe"}
    ))
    assert response.action == "ALLOW"
    assert response.policy_status == "available"


def test_agent_tool_permission_denies_before_policy_or_execution() -> None:
    service = SecurityService()
    response = service.check_agent_tool(
        "agent-research", "calculator", {"value": 1}
    )
    assert response.action == "BLOCK"
    assert response.allowed is False
    assert service.audit_logger.events()[0].status == "blocked"
    assert not hasattr(service.tool_gateway, "execute")


def test_unknown_agent_is_denied_and_audited_as_unknown() -> None:
    service = SecurityService()
    response = service.check_agent_tool(
        "unregistered-agent", "search", {"query": "safe"}
    )
    event = service.audit_logger.events()[0]
    assert response.action == "BLOCK"
    assert event.agent_id == "unknown_agent"
    assert event.permission_subject == "search"


def test_unknown_agent_cannot_authorize_content_bearing_data_request() -> None:
    response = check_agent_data_content(AgentDataContentCheckRequest(
        agent_id="unregistered-agent",
        data_type="public",
        destination="internal",
        content="Synthetic project text with no sensitive pattern.",
    ))

    assert response.scan.scan_status == "scanned"
    assert response.decision.action == "BLOCK"
    assert response.decision.allowed is False


def test_agent_cannot_exceed_data_classification_scope() -> None:
    response = check_agent_data_content(AgentDataContentCheckRequest(
        agent_id="agent-research",
        data_type="internal",
        destination="internal",
        content="Routine project summary.",
    ))
    assert response.decision.action == "BLOCK"
    assert response.scan.scan_status == "scanned"


def test_unverified_public_label_cannot_authorize_internal_compensation_content() -> None:
    content = "Internal compensation table: employee A earns 250000 per year."
    service = SecurityService()

    scan, decision = service.check_agent_data_with_content(
        "agent-research", "public", "internal", content
    )

    assert scan.scan_status == "scanned"
    assert scan.classification == "no_pattern_detected"
    assert decision.action == "REVIEW"
    assert decision.allowed is False
    event = service.audit_logger.events()[0]
    assert event.status == "review"
    assert event.recommended_action == "REVIEW"
    assert content not in str(event.model_dump())


@pytest.mark.parametrize(
    ("agent_id", "data_type", "expected_action"),
    [
        ("agent-research", "public", "REVIEW"),
        ("agent-analyst", "internal", "REVIEW"),
        ("agent-analyst", "unrecognized", "BLOCK"),
    ],
)
def test_unverified_or_unknown_agent_data_classification_fails_closed(
    agent_id: str, data_type: str, expected_action: str
) -> None:
    service = SecurityService()

    scan, decision = service.check_agent_data_with_content(
        agent_id,
        data_type,
        "internal",
        "Synthetic project notes without recognized DLP patterns.",
    )

    assert scan.scan_status == "scanned"
    assert decision.action == expected_action
    assert decision.allowed is False


def test_agent_sensitive_data_dlp_and_policy_decisions_remain_effective() -> None:
    service = SecurityService()
    secret = "TEST_ONLY_AGENT_SCOPE_API_KEY"

    scan, decision = service.check_agent_data_with_content(
        "agent-research", "public", "external", f"api_key={secret}"
    )

    assert scan.indicators == ("api_key",)
    assert decision.action == "BLOCK"
    assert decision.allowed is False
    event = service.audit_logger.events()[0]
    assert event.status == "blocked"
    assert event.recommended_action == "BLOCK"
    assert secret not in str(scan.model_dump())
    assert secret not in str(event.model_dump())


def test_in_scope_but_unverified_data_does_not_override_policy_review() -> None:
    service = SecurityService()
    content = "Synthetic internal project notes with no known DLP pattern."

    scan, decision = service.check_agent_data_with_content(
        "agent-analyst", "internal", "internal", content
    )

    assert scan.classification == "no_pattern_detected"
    assert decision.action == "REVIEW"
    assert decision.allowed is False
    event = service.audit_logger.events()[0]
    # The configured policy would allow this label, but the classifier has not
    # verified it; the final monitoring status therefore remains REVIEW.
    assert event.policy_decision == "ALLOW"
    assert event.recommended_action == "REVIEW"
    assert event.status == "review"
    assert service.audit_logger.summary()["review_events"] == 1


def test_agent_data_response_and_audit_never_expose_raw_content_or_secret(
    caplog,
) -> None:
    secret = "TEST_ONLY_AGENT_CONTENT_SECRET"
    content = f"api_key={secret}"
    service = SecurityService()

    with caplog.at_level(logging.INFO):
        scan, decision = service.check_agent_data_with_content(
            "agent-analyst", "internal", "internal", content
        )

    event = service.audit_logger.events()[0]
    serialized = str({"scan": scan.model_dump(), "decision": decision.model_dump()})
    assert "api_key" in scan.indicators
    assert secret not in serialized
    assert secret not in str(event.model_dump())
    assert content not in caplog.text
    assert secret not in caplog.text


def test_dlp_escalation_cannot_be_bypassed_by_public_agent_label() -> None:
    secret = "TEST_ONLY_AGENT_SCOPE_API_KEY"
    response = check_agent_data_content(AgentDataContentCheckRequest(
        agent_id="agent-research",
        data_type="public",
        destination="internal",
        content=f"api_key={secret}",
    ))
    assert response.scan.indicators == ("api_key",)
    assert response.decision.action == "BLOCK"
    assert secret not in str(response.model_dump())


def test_agent_audit_contains_only_allowlisted_metadata(
    caplog,
) -> None:
    secret = "TEST_ONLY_RAW_TOOL_ARGUMENT_SECRET"
    service = SecurityService()
    with caplog.at_level(logging.INFO):
        service.check_agent_tool(
            "agent-research", "search", {"query": secret, "api_key": secret}
        )
    event = service.audit_logger.events()[0]
    assert event.agent_id == "agent-research"
    assert event.permission_kind == "tool"
    assert event.permission_subject == "search"
    assert secret not in caplog.text
    assert secret not in str(event.model_dump())


def test_dashboard_permissions_view_uses_registry_and_recorded_decisions(monkeypatch) -> None:
    import backend.api.security as security_api

    service = SecurityService()
    service.check_agent_tool("agent-research", "search", {})
    service.check_agent_tool("agent-research", "calculator", {})
    monkeypatch.setattr(security_api, "security_service", service)

    view = agent_permissions_view(limit=50)

    assert {profile.agent_id for profile in view.agents} == {
        "agent-research", "agent-analyst"
    }
    assert len(view.recent_decisions) == 2
    assert len(view.denied_requests) == 1
    assert "does not authenticate" in view.identity_note
