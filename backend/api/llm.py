"""Security-gated API routes for a locally hosted Ollama model."""

from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, StringConstraints

from backend.core.config import settings
from backend.core.ollama_adapter import (
    OllamaAdapter,
    OllamaError,
    OllamaHealth,
    OllamaHTTPError,
    OllamaResponseError,
    OllamaTimeoutError,
    OllamaUnavailableError,
)
from backend.core.security_service import SecurityAnalysis, SecurityService
from backend.gateway.input_gateway import (
    InputTooLargeError,
    InputValidationError,
    SecurityInputRequest,
)
from backend.policy.dlp import DLPResult


class SafeValidationRoute(APIRoute):
    """Avoid reflecting invalid request values in this router's 422 responses."""

    def get_route_handler(self):
        original_handler = super().get_route_handler()

        async def safe_handler(request: Request):
            try:
                return await original_handler(request)
            except RequestValidationError:
                return JSONResponse(
                    status_code=422,
                    content={"detail": "Invalid LLM request."},
                )

        return safe_handler


router = APIRouter(
    prefix="/api/llm",
    tags=["LLM"],
    route_class=SafeValidationRoute,
)

LLMMessage = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=32_768),
]


class LLMChatRequest(BaseModel):
    """One user message; callers cannot select models or add hidden controls."""

    model_config = ConfigDict(extra="forbid")

    message: LLMMessage


class LLMChatResponse(BaseModel):
    """A model response released only after input and output security checks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    model: str
    action: Literal["ALLOW"]
    response: str


def get_security_service() -> SecurityService:
    """Resolve the same service instance used by the versioned Security API."""
    from backend.api.security import security_service

    return security_service


def get_ollama_adapter() -> OllamaAdapter:
    """Create a cheap adapter; no client connection is opened at startup."""
    return OllamaAdapter()


@router.get("/health", response_model=OllamaHealth)
async def ollama_health(
    adapter: OllamaAdapter = Depends(get_ollama_adapter),
) -> OllamaHealth:
    """Report local API reachability and configured model availability."""
    return await adapter.health()


def _controls_available(service: SecurityService) -> bool:
    """Require each control used by this request path to be callable and ready."""
    try:
        policy = getattr(service, "policy_engine", None)
        return (
            callable(getattr(service, "analyze", None))
            and callable(getattr(getattr(service, "input_gateway", None), "normalize", None))
            and callable(getattr(getattr(service, "threat_detector", None), "analyze", None))
            and callable(getattr(getattr(service, "risk_engine", None), "assess", None))
            and getattr(policy, "is_available", False) is True
            and callable(getattr(getattr(service, "dlp_engine", None), "scan", None))
            and callable(getattr(getattr(service, "audit_logger", None), "record", None))
        )
    except Exception:
        return False


def _record_llm_decision(
    service: SecurityService,
    action: Literal["ALLOW", "REVIEW", "BLOCK"],
    request_id: UUID,
    analysis: SecurityAnalysis | None = None,
) -> bool:
    """Write allow-listed pipeline metadata only; never accepts request text."""
    try:
        service.audit_logger.record(
            "llm_chat",
            action,
            action == "ALLOW",
            request_id=request_id,
            source_type="api",
            threat_category=analysis.threat if analysis is not None else "not_assessed",
            severity=analysis.severity if analysis is not None else "UNKNOWN",
            risk_score=analysis.risk_score if analysis is not None else None,
        )
        return True
    except Exception:
        return False


def _raise_safe_error(
    status_code: int,
    detail: str,
    request_id: UUID,
) -> None:
    raise HTTPException(
        status_code=status_code,
        detail=detail,
        headers={"X-Request-ID": str(request_id)},
    ) from None


@router.post("/chat", response_model=LLMChatResponse)
async def chat(
    request: LLMChatRequest,
    service: SecurityService = Depends(get_security_service),
    adapter: OllamaAdapter = Depends(get_ollama_adapter),
) -> LLMChatResponse:
    """Analyze untrusted input, generate locally, scan output, then return it."""
    if len(request.message) > settings.llm_max_message_chars:
        _raise_safe_error(422, "Message exceeds the configured length limit.", uuid4())

    if not _controls_available(service):
        request_id = uuid4()
        _record_llm_decision(service, "REVIEW", request_id)
        _raise_safe_error(503, "Input security controls are unavailable.", request_id)

    try:
        analysis = service.analyze(
            SecurityInputRequest(
                source_type="api",
                source_name="llm-chat-request",
                content=request.message,
                metadata={},
            )
        )
    except InputTooLargeError:
        request_id = uuid4()
        _record_llm_decision(service, "REVIEW", request_id)
        _raise_safe_error(413, "Message exceeds the input analysis limit.", request_id)
    except InputValidationError:
        request_id = uuid4()
        _record_llm_decision(service, "REVIEW", request_id)
        _raise_safe_error(422, "Message could not be validated.", request_id)
    except Exception:
        request_id = uuid4()
        _record_llm_decision(service, "REVIEW", request_id)
        _raise_safe_error(503, "Input security analysis failed.", request_id)

    if not isinstance(analysis, SecurityAnalysis):
        request_id = uuid4()
        _record_llm_decision(service, "REVIEW", request_id)
        _raise_safe_error(503, "Input security analysis was inconclusive.", request_id)

    request_id = analysis.input_id
    if analysis.action == "BLOCK":
        audit_ok = _record_llm_decision(service, "BLOCK", request_id, analysis)
        if not audit_ok:
            _raise_safe_error(503, "Security audit is unavailable.", request_id)
        _raise_safe_error(403, "Input was blocked by security policy.", request_id)

    if analysis.action == "REVIEW":
        audit_ok = _record_llm_decision(service, "REVIEW", request_id, analysis)
        if not audit_ok:
            _raise_safe_error(503, "Security audit is unavailable.", request_id)
        _raise_safe_error(409, "Input requires security review.", request_id)

    assessed = (
        analysis.analysis_status == "analyzed"
        and analysis.detection_result is not None
        and analysis.threat != "not_assessed"
        and analysis.risk_score is not None
        and analysis.severity != "UNKNOWN"
    )
    if not assessed:
        _record_llm_decision(service, "REVIEW", request_id, analysis)
        _raise_safe_error(409, "Input requires security review.", request_id)
    try:
        generated_text = await adapter.chat(request.message)
    except OllamaTimeoutError:
        status_code, detail = 504, "Local model request timed out."
    except OllamaUnavailableError:
        status_code, detail = 503, "Local model service or model is unavailable."
    except (OllamaHTTPError, OllamaResponseError):
        status_code, detail = 502, "Local model returned an unusable response."
    except OllamaError:
        status_code, detail = 502, "Local model request failed."
    except Exception:
        status_code, detail = 502, "Local model request failed."
    else:
        status_code = 0
        detail = ""

    if status_code:
        if not _record_llm_decision(service, "REVIEW", request_id, analysis):
            _raise_safe_error(503, "Security audit is unavailable.", request_id)
        _raise_safe_error(status_code, detail, request_id)

    try:
        scan = service.dlp_engine.scan(generated_text)
    except Exception:
        scan = None
    if not isinstance(scan, DLPResult):
        if not _record_llm_decision(service, "REVIEW", request_id, analysis):
            _raise_safe_error(503, "Security audit is unavailable.", request_id)
        _raise_safe_error(503, "Output security screening is unavailable.", request_id)

    if scan.contains_sensitive_data is True:
        if not _record_llm_decision(service, "BLOCK", request_id, analysis):
            _raise_safe_error(503, "Security audit is unavailable.", request_id)
        _raise_safe_error(502, "Model response was withheld by security screening.", request_id)

    if not (
        scan.scan_status == "scanned"
        and scan.classification == "no_pattern_detected"
        and scan.contains_sensitive_data is False
        and scan.data_type == "unclassified"
        and not scan.indicators
    ):
        if not _record_llm_decision(service, "REVIEW", request_id, analysis):
            _raise_safe_error(503, "Security audit is unavailable.", request_id)
        _raise_safe_error(503, "Output security screening was inconclusive.", request_id)

    if not _record_llm_decision(service, "ALLOW", request_id, analysis):
        _raise_safe_error(503, "Security audit is unavailable.", request_id)
    return LLMChatResponse(
        request_id=request_id,
        model=adapter.model,
        action="ALLOW",
        response=generated_text,
    )
