"""Deterministic pattern-based detection of potentially sensitive text.

No match means only that these patterns found nothing; it does not prove that
content is free of sensitive data.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict

DLPDataType = Literal["confidential", "unclassified", "unknown"]
DLPClassification = Literal["sensitive", "no_pattern_detected", "unknown"]
DLPSeverity = Literal["HIGH", "MEDIUM", "NONE", "UNKNOWN"]
DLPScanStatus = Literal["scanned", "invalid_input", "too_large"]


class DLPResult(BaseModel):
    """Redacted scan result containing labels and indicator names only."""

    model_config = ConfigDict(frozen=True)

    data_type: DLPDataType
    classification: DLPClassification
    indicators: tuple[str, ...]
    contains_sensitive_data: bool | None
    severity: DLPSeverity
    scan_status: DLPScanStatus


class DLPEngine:
    """Scan text for common sensitive patterns without logging or retaining it."""

    _MAX_CONTENT_BYTES = 1_048_576

    _PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
        (
            "api_key",
            re.compile(
                r"\bapi[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_-]{8,}"
                r"|\bAIza[0-9A-Za-z_-]{20,}\b"
                r"|\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b",
                re.IGNORECASE,
            ),
        ),
        (
            "bearer_token",
            re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
        ),
        (
            "password",
            re.compile(
                r"\b(?:password|passwd)\s*[:=]\s*['\"]?[^'\"\s,;]{4,}",
                re.IGNORECASE,
            ),
        ),
        (
            "secret",
            re.compile(
                r"\bsecret\s*[:=]\s*['\"]?[^'\"\s,;]{4,}", re.IGNORECASE
            ),
        ),
        (
            "private_key",
            re.compile(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
                re.IGNORECASE,
            ),
        ),
        (
            "cloud_credential",
            re.compile(
                r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
                r"|\baws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{20,}"
                r"|\bAccountKey\s*=\s*['\"]?[A-Za-z0-9/+=]{20,}",
                re.IGNORECASE,
            ),
        ),
        (
            "email",
            re.compile(
                r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE
            ),
        ),
        (
            "phone",
            re.compile(
                r"(?<!\w)(?:\+?\d{1,3}[ .-]?)?"
                r"(?:\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}(?!\w)"
            ),
        ),
    )

    _HIGH_SEVERITY_INDICATORS = frozenset(
        {"api_key", "bearer_token", "password", "secret", "private_key", "cloud_credential"}
    )

    def scan(self, content: object) -> DLPResult:
        """Return indicator names only; invalid and oversized content stays unknown."""
        if type(content) is not str:
            return self._unscanned("invalid_input")
        if len(content) > self._MAX_CONTENT_BYTES:
            return self._unscanned("too_large")

        try:
            if len(content.encode("utf-8")) > self._MAX_CONTENT_BYTES:
                return self._unscanned("too_large")
        except UnicodeError:
            return self._unscanned("invalid_input")

        indicators = tuple(
            name for name, pattern in self._PATTERNS if pattern.search(content)
        )
        if not indicators:
            return DLPResult(
                data_type="unclassified",
                classification="no_pattern_detected",
                indicators=(),
                contains_sensitive_data=False,
                severity="NONE",
                scan_status="scanned",
            )

        severity: DLPSeverity = (
            "HIGH"
            if self._HIGH_SEVERITY_INDICATORS.intersection(indicators)
            else "MEDIUM"
        )
        return DLPResult(
            data_type="confidential",
            classification="sensitive",
            indicators=indicators,
            contains_sensitive_data=True,
            severity=severity,
            scan_status="scanned",
        )

    @staticmethod
    def _unscanned(status: Literal["invalid_input", "too_large"]) -> DLPResult:
        return DLPResult(
            data_type="unknown",
            classification="unknown",
            indicators=(),
            contains_sensitive_data=None,
            severity="UNKNOWN",
            scan_status=status,
        )
