"""Environment-backed application settings."""

import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")


class Settings(BaseModel):
    """Runtime settings loaded from environment variables and the project .env."""

    service_name: str = "AgentShield"
    database_url: str = "sqlite:///./agentshield.db"
    log_level: Literal["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"] = "INFO"


settings = Settings(
    service_name=os.getenv("SERVICE_NAME", "AgentShield"),
    database_url=os.getenv("DATABASE_URL", "sqlite:///./agentshield.db"),
    log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
)
