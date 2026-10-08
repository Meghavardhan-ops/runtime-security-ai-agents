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
    input_max_content_bytes: int = 65_536
    input_max_source_name_length: int = 255
    input_max_metadata_bytes: int = 16_384


settings = Settings(
    service_name=os.getenv("SERVICE_NAME", "AgentShield"),
    database_url=os.getenv("DATABASE_URL", "sqlite:///./agentshield.db"),
    log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
    input_max_content_bytes=os.getenv("INPUT_MAX_CONTENT_BYTES", "65536"),
    input_max_source_name_length=os.getenv("INPUT_MAX_SOURCE_NAME_LENGTH", "255"),
    input_max_metadata_bytes=os.getenv("INPUT_MAX_METADATA_BYTES", "16384"),
)
