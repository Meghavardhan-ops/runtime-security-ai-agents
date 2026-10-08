"""Validate and normalize untrusted external content without executing it."""

import hashlib
import json
import logging
import unicodedata
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from backend.core.config import settings

logger = logging.getLogger(__name__)

SourceType = Literal["file", "email", "web", "api", "database", "text"]


class SecurityInputRequest(BaseModel):
    """Caller-supplied input fields; gateway-owned fields are not accepted."""

    model_config = ConfigDict(extra="forbid")

    source_type: SourceType
    source_name: str
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityInput(BaseModel):
    """Normalized record passed to future security-pipeline components."""

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    source_type: SourceType
    source_name: str
    content: str
    metadata: dict[str, Any]
    trusted: Literal[False] = False
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class InputValidationError(ValueError):
    """Raised when content is invalid or exceeds a configured gateway limit."""


class InputTooLargeError(InputValidationError):
    """Raised when a configured size or length limit is exceeded."""


class InputGateway:
    """Create safe, metadata-rich records without interpreting submitted data."""

    def __init__(
        self,
        max_content_bytes: int | None = None,
        max_source_name_length: int | None = None,
        max_metadata_bytes: int | None = None,
    ) -> None:
        self.max_content_bytes = (
            settings.input_max_content_bytes
            if max_content_bytes is None
            else max_content_bytes
        )
        self.max_source_name_length = (
            settings.input_max_source_name_length
            if max_source_name_length is None
            else max_source_name_length
        )
        self.max_metadata_bytes = (
            settings.input_max_metadata_bytes
            if max_metadata_bytes is None
            else max_metadata_bytes
        )
        if min(
            self.max_content_bytes,
            self.max_source_name_length,
            self.max_metadata_bytes,
        ) <= 0:
            raise ValueError("Input gateway limits must be positive")

    def normalize(self, request: SecurityInputRequest) -> SecurityInput:
        """Validate, canonicalize, hash, and record one untrusted input."""
        source_name = unicodedata.normalize("NFC", request.source_name).strip()
        if not source_name:
            raise InputValidationError("source_name must not be empty")
        if len(source_name) > self.max_source_name_length:
            raise InputTooLargeError("source_name exceeds the configured length limit")
        if any(ord(character) < 32 or ord(character) == 127 for character in source_name):
            raise InputValidationError("source_name must not contain control characters")

        content = unicodedata.normalize("NFC", request.content)
        content = content.replace("\r\n", "\n").replace("\r", "\n")
        if not content.strip():
            raise InputValidationError("content must not be empty")
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > self.max_content_bytes:
            raise InputTooLargeError("content exceeds the configured byte limit")

        try:
            metadata_bytes = json.dumps(
                request.metadata,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError) as error:
            raise InputValidationError("metadata must contain valid JSON values") from error
        if len(metadata_bytes) > self.max_metadata_bytes:
            raise InputTooLargeError("metadata exceeds the configured byte limit")

        received_at = datetime.now(timezone.utc)
        record = SecurityInput(
            id=uuid4(),
            source_type=request.source_type,
            source_name=source_name,
            content=content,
            metadata=request.metadata,
            trusted=False,
            received_at=received_at,
            content_hash=hashlib.sha256(content_bytes).hexdigest(),
        )

        # JSON-escape the attacker-controlled name to keep it to one log field.
        logger.info(
            "input_id=%s source_type=%s source_name=%s received_at=%s "
            "trusted=%s content_size_bytes=%s content_hash=%s",
            record.id,
            record.source_type,
            json.dumps(record.source_name, ensure_ascii=True),
            record.received_at.isoformat(),
            record.trusted,
            len(content_bytes),
            record.content_hash,
        )
        return record
