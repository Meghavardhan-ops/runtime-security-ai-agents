"""FastAPI application entry point."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from backend.api.health import router as health_router
from backend.api.inputs import router as inputs_router
from backend.api.llm import router as llm_router
from backend.api.security import router as security_router
from backend.core.config import settings
from backend.core.logging_config import configure_logging

configure_logging()

app = FastAPI(title=settings.service_name, version="0.1.0")
app.include_router(health_router)
app.include_router(inputs_router)
app.include_router(security_router)
app.include_router(llm_router)

# The dependency-free dashboard is served by the same origin as the API.
dashboard_dir = Path(__file__).resolve().parent.parent / "dashboard"
app.mount("/dashboard", StaticFiles(directory=dashboard_dir, html=True), name="dashboard")
