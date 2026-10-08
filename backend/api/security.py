"""Versioned, check-only Security API routes."""

from typing import Any, Annotated

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from backend.core.security_service import SecurityAnalysis, SecurityService
from backend.gateway.input_gateway import (
    InputTooLargeError,
    InputValidationError,
    SecurityInput,
    SecurityInputRequest,
)
from backend.policy.policy_engine import SecurityDecision

router = APIRouter(prefix="/api/v1/security", tags=["Security"])
security_service = SecurityService()

NonEmptyName = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)
]
NonEmptyTarget = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=512)
]


class ToolCheckRequest(BaseModel):
    """Untrusted tool request metadata; it is never executed."""

    model_config = ConfigDict(extra="forbid")

    tool_name: NonEmptyName
    arguments: dict[str, Any] = Field(default_factory=dict)


class DataCheckRequest(BaseModel):
    """Caller-provided classification and destination labels."""

    model_config = ConfigDict(extra="forbid")

    data_type: NonEmptyName
    destination: NonEmptyName


class ActionCheckRequest(BaseModel):
    """Action metadata for a check-only authorization decision."""

    model_config = ConfigDict(extra="forbid")

    action: NonEmptyName
    target: NonEmptyTarget


class ToolCheckResponse(SecurityDecision):
    """Decision plus the requested tool identifier, without its arguments."""

    tool_name: str


class SecurityStatus(BaseModel):
    """Implementation status of the security control-plane components."""

    security_router: str = "active"
    input_gateway: str = "active"
    threat_detector: str = "active"
    risk_engine: str = "not_implemented"
    policy_engine: str = "not_implemented"
    data_classifier: str = "not_implemented"
    tool_gateway: str = "not_implemented"
    audit_logging: str = "active"


@router.post("/analyze", response_model=SecurityAnalysis)
def analyze_input(
    request: SecurityInputRequest | SecurityInput,
) -> SecurityAnalysis:
    """Normalize request through the Input Gateway, then call safe stubs."""
    # Accept either the original gateway request or its response, but always
    # regenerate gateway-owned fields so callers cannot bypass normalization.
    if isinstance(request, SecurityInput):
        gateway_request = SecurityInputRequest(
            source_type=request.source_type,
            source_name=request.source_name,
            content=request.content,
            metadata=request.metadata,
        )
    else:
        gateway_request = request

    try:
        return security_service.analyze(gateway_request)
    except InputTooLargeError as error:
        raise HTTPException(status_code=413, detail=str(error)) from error
    except InputValidationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.post("/check-tool", response_model=ToolCheckResponse)
def check_tool(request: ToolCheckRequest) -> ToolCheckResponse:
    """Return a decision only; no tool is invoked."""
    decision = security_service.check_tool(request.tool_name, request.arguments)
    return ToolCheckResponse(tool_name=request.tool_name, **decision.model_dump())


@router.post("/check-data", response_model=SecurityDecision)
def check_data(request: DataCheckRequest) -> SecurityDecision:
    """Return a decision only; no data is transferred."""
    return security_service.check_data(request.data_type, request.destination)


@router.post("/check-action", response_model=SecurityDecision)
def check_action(request: ActionCheckRequest) -> SecurityDecision:
    """Return a decision only; the requested action is never performed."""
    return security_service.check_action(request.action, request.target)


@router.get("/status", response_model=SecurityStatus)
def security_status() -> SecurityStatus:
    """Report active interfaces and components that remain unimplemented."""
    return SecurityStatus()
