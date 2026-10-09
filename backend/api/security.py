"""Versioned, check-only Security API routes."""

from typing import Any, Annotated
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from backend.core.config import settings
from backend.core.security_service import SecurityAnalysis, SecurityService
from backend.gateway.input_gateway import (
    InputTooLargeError,
    InputValidationError,
    SecurityInput,
    SecurityInputRequest,
)
from backend.policy.policy_engine import SecurityDecision
from backend.monitor.audit_logger import MonitoringEvent
from backend.policy.dlp import DLPResult
from backend.policy.agent_permissions import AgentPermissionProfile
from backend.gateway.image_gateway import (
    ImageGateway,
    ImageOCRError,
    ImageUploadTooLargeError,
    InvalidImageError,
    OCREngineUnavailableError,
    UnsupportedImageFormatError,
)

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


class DataContentCheckRequest(BaseModel):
    """Untrusted content to scan; caller labels are context, never scan results."""

    model_config = ConfigDict(extra="forbid")

    data_type: NonEmptyName
    destination: NonEmptyName
    content: str


class AgentToolCheckRequest(BaseModel):
    """A synthetic demo agent ID and inert tool request metadata."""

    model_config = ConfigDict(extra="forbid")

    agent_id: NonEmptyName
    tool_name: NonEmptyName
    arguments: dict[str, Any] = Field(default_factory=dict)


class AgentDataContentCheckRequest(BaseModel):
    """Synthetic agent context and content to scan before data authorization."""

    model_config = ConfigDict(extra="forbid")

    agent_id: NonEmptyName
    data_type: NonEmptyName
    destination: NonEmptyName
    content: str


class DataContentCheckResponse(BaseModel):
    scan: DLPResult
    decision: SecurityDecision


class AgentToolCheckResponse(SecurityDecision):
    agent_id: str
    tool_name: str


class AgentDataContentCheckResponse(BaseModel):
    scan: DLPResult
    decision: SecurityDecision


class AgentPermissionsView(BaseModel):
    agents: list[AgentPermissionProfile]
    recent_decisions: list[MonitoringEvent]
    denied_requests: list[MonitoringEvent]
    identity_note: str


class ToolCheckResponse(SecurityDecision):
    """Decision plus the requested tool identifier, without its arguments."""

    tool_name: str


class SecurityStatus(BaseModel):
    """Implementation status of the security control-plane components."""

    security_router: str = "active"
    input_gateway: str = "active"
    threat_detector: str = "active"
    risk_engine: str = "active"
    policy_engine: str = "active"
    data_classifier: str = "incomplete"
    dlp_engine: str = "active"
    tool_gateway: str = "active"
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


async def _read_bounded_image_upload(upload: UploadFile) -> bytes:
    """Read at most the configured image limit plus one detection byte."""
    max_bytes = settings.image_max_upload_bytes
    if upload.size is not None and upload.size > max_bytes:
        raise ImageUploadTooLargeError from None

    data = bytearray()
    while True:
        remaining_with_probe = max_bytes - len(data) + 1
        chunk = await upload.read(min(64 * 1024, remaining_with_probe))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > max_bytes:
            raise ImageUploadTooLargeError from None
    return bytes(data)


def _unassessed_image_response() -> SecurityAnalysis:
    """Return and monitor a fail-closed REVIEW when OCR finds no usable text."""
    request_id = uuid4()
    security_service.audit_logger.record(
        "analyze",
        "REVIEW",
        False,
        request_id=request_id,
        source_type="file",
        threat_category="not_assessed",
        severity="UNKNOWN",
        risk_score=None,
    )
    return SecurityAnalysis(
        input_id=request_id,
        analysis_status="fail_closed",
        risk_score=None,
        severity="UNKNOWN",
        threat="not_assessed",
        action="REVIEW",
        reason=(
            "OCR found no usable text; the image remains unassessed and requires review."
        ),
    )


@router.post("/analyze-image", response_model=SecurityAnalysis)
async def analyze_image(file: UploadFile = File(...)) -> SecurityAnalysis:
    """OCR a bounded PNG/JPEG upload and analyze extracted text as untrusted input."""
    try:
        image_bytes = await _read_bounded_image_upload(file)
        extracted_text = ImageGateway().extract_text(image_bytes)
    except ImageUploadTooLargeError:
        raise HTTPException(
            status_code=413,
            detail="Image exceeds the configured upload or pixel limit.",
        ) from None
    except UnsupportedImageFormatError:
        raise HTTPException(
            status_code=415,
            detail="Unsupported image format. Upload a PNG or JPEG image.",
        ) from None
    except InvalidImageError:
        raise HTTPException(
            status_code=422,
            detail="The upload is not a valid, decodable PNG or JPEG image.",
        ) from None
    except OCREngineUnavailableError:
        raise HTTPException(
            status_code=503,
            detail="OCR is unavailable. Install Tesseract or configure TESSERACT_CMD.",
        ) from None
    except ImageOCRError:
        raise HTTPException(
            status_code=502,
            detail="OCR failed; the image was not analyzed.",
        ) from None
    finally:
        await file.close()

    if not extracted_text:
        return _unassessed_image_response()

    try:
        return security_service.analyze(
            SecurityInputRequest(
                source_type="file",
                source_name="uploaded-image",
                content=extracted_text,
                metadata={},
            )
        )
    except InputTooLargeError:
        raise HTTPException(
            status_code=413,
            detail="Extracted image text exceeds the analysis limit.",
        ) from None
    except InputValidationError:
        # This includes OCR output that normalizes to empty or invalid text.
        return _unassessed_image_response()


@router.post("/check-tool", response_model=ToolCheckResponse)
def check_tool(request: ToolCheckRequest) -> ToolCheckResponse:
    """Return a decision only; no tool is invoked."""
    decision = security_service.check_tool(request.tool_name, request.arguments)
    return ToolCheckResponse(tool_name=request.tool_name, **decision.model_dump())


@router.post("/check-data", response_model=SecurityDecision)
def check_data(request: DataCheckRequest) -> SecurityDecision:
    """Return a decision only; no data is transferred."""
    return security_service.check_data(request.data_type, request.destination)


@router.post("/check-data-content", response_model=DataContentCheckResponse)
def check_data_content(request: DataContentCheckRequest) -> DataContentCheckResponse:
    """Scan supplied content and return only redacted indicators plus a decision."""
    scan, decision = security_service.check_data_with_content(
        request.data_type, request.destination, request.content
    )
    return DataContentCheckResponse(scan=scan, decision=decision)


@router.post("/check-agent-tool", response_model=AgentToolCheckResponse)
def check_agent_tool(request: AgentToolCheckRequest) -> AgentToolCheckResponse:
    """Authorize a tool for a synthetic demo agent; never invoke the tool."""
    decision = security_service.check_agent_tool(
        request.agent_id, request.tool_name, request.arguments
    )
    return AgentToolCheckResponse(
        agent_id=request.agent_id,
        tool_name=request.tool_name,
        **decision.model_dump(),
    )


@router.post("/check-agent-data-content", response_model=AgentDataContentCheckResponse)
def check_agent_data_content(
    request: AgentDataContentCheckRequest,
) -> AgentDataContentCheckResponse:
    """Scan supplied content, then enforce synthetic agent and policy scopes."""
    scan, decision = security_service.check_agent_data_with_content(
        request.agent_id,
        request.data_type,
        request.destination,
        request.content,
    )
    return AgentDataContentCheckResponse(scan=scan, decision=decision)


@router.get("/agent-permissions", response_model=AgentPermissionsView)
def agent_permissions_view(
    limit: int = Query(default=50, ge=1, le=200),
) -> AgentPermissionsView:
    """Expose local demo permissions and safe recent authorization metadata."""
    decisions = [
        event
        for event in security_service.audit_logger.events(limit=1000)
        if event.agent_id is not None
    ][:limit]
    return AgentPermissionsView(
        agents=list(security_service.agent_permissions.list_profiles()),
        recent_decisions=decisions,
        denied_requests=[event for event in decisions if event.status == "blocked"],
        identity_note=(
            "Agent IDs are caller supplied demonstration labels. This API does not "
            "authenticate or verify agent identity."
        ),
    )


@router.post("/check-action", response_model=SecurityDecision)
def check_action(request: ActionCheckRequest) -> SecurityDecision:
    """Return a decision only; the requested action is never performed."""
    return security_service.check_action(request.action, request.target)


@router.get("/status", response_model=SecurityStatus)
def security_status() -> SecurityStatus:
    """Report implemented controls and explicitly incomplete placeholders."""
    service = security_service
    policy_available = service.policy_engine.is_available
    return SecurityStatus(
        security_router="active",
        input_gateway="active",
        threat_detector="active",
        risk_engine="active",
        policy_engine="active" if policy_available else "unavailable",
        data_classifier=(
            "active" if service.data_classifier.is_available else "incomplete"
        ),
        dlp_engine="active",
        tool_gateway="active",
        audit_logging="active",
    )


@router.get("/monitoring", response_model=list[MonitoringEvent])
def security_monitoring(
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[MonitoringEvent]:
    """List the newest metadata-only events recorded by the audit logger."""
    return security_service.audit_logger.events(limit)


@router.get("/monitoring/summary")
def security_monitoring_summary() -> dict[str, object]:
    """Summarize actual in-process audit events."""
    return security_service.audit_logger.summary()
