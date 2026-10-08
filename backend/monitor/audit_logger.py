"""Metadata-only security decision logging."""

import logging
from typing import Literal
from uuid import UUID

logger = logging.getLogger(__name__)

AuditEvent = Literal["analyze", "check_tool", "check_data", "check_action"]


class AuditLogger:
    """Record decision metadata without logging content or request arguments."""

    def record(
        self,
        event: AuditEvent,
        decision: str,
        allowed: bool | None,
        request_id: UUID | None = None,
    ) -> None:
        """Write only controlled event names, IDs, and decision fields."""
        logger.info(
            "security_audit event=%s request_id=%s decision=%s allowed=%s",
            event,
            request_id or "-",
            decision,
            allowed,
        )
