"""Environment-backed application settings."""

import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field

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
    image_max_upload_bytes: int = Field(default=5_242_880, gt=0)
    image_max_pixels: int = Field(default=12_000_000, gt=0)
    tesseract_cmd: str = ""


settings = Settings(
    service_name=os.getenv("SERVICE_NAME", "AgentShield"),
    database_url=os.getenv("DATABASE_URL", "sqlite:///./agentshield.db"),
    log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
    input_max_content_bytes=os.getenv("INPUT_MAX_CONTENT_BYTES", "65536"),
    input_max_source_name_length=os.getenv("INPUT_MAX_SOURCE_NAME_LENGTH", "255"),
    input_max_metadata_bytes=os.getenv("INPUT_MAX_METADATA_BYTES", "16384"),
    image_max_upload_bytes=os.getenv("IMAGE_MAX_UPLOAD_BYTES", "5242880"),
    image_max_pixels=os.getenv("IMAGE_MAX_PIXELS", "12000000"),
    tesseract_cmd=os.getenv("TESSERACT_CMD", ""),
)
