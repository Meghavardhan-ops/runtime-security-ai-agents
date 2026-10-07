"""FastAPI application entry point."""

from fastapi import FastAPI

from backend.api.health import router as health_router
from backend.api.security import router as security_router
from backend.core.config import settings
from backend.core.logging_config import configure_logging

configure_logging()

app = FastAPI(title=settings.service_name, version="0.1.0")
app.include_router(health_router)
app.include_router(security_router)
