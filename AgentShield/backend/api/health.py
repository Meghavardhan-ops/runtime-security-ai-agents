"""Health check endpoint."""

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

from backend.core.config import settings

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Response returned when the service is ready to accept requests."""

    status: Literal["healthy"]
    service: str


@router.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    """Return the service health and configured service name."""
    return HealthResponse(status="healthy", service=settings.service_name)
