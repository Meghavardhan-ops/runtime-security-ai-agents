"""Normalization, evidence scoring, and detector result classification."""

import unicodedata

from backend.detector.models import DetectionResult
from backend.detector.rules import detect_indicators

INDICATOR_ORDER = (
    "instruction_override",
    "system_prompt_extraction",
    "indirect_instruction",
    "suspicious_instruction_context",
    "credential_access",
    "api_key_access",
    "password_access",
    "authentication_token_access",
    "sensitive_file_access",
    "external_data_exfiltration",
    "email_exfiltration",
    "http_exfiltration",
    "upload_exfiltration",
    "tool_invocation",
    "external_api_request",
    "restricted_resource_access",
    "harmful_instruction_request",
)

INDICATOR_WEIGHTS = {
    "instruction_override": 35,
    "system_prompt_extraction": 40,
    "indirect_instruction": 12,
    "suspicious_instruction_context": 8,
    "credential_access": 28,
    "api_key_access": 18,
    "password_access": 18,
    "authentication_token_access": 20,
    "sensitive_file_access": 25,
    "external_data_exfiltration": 42,
    "email_exfiltration": 6,
    "http_exfiltration": 6,
    "upload_exfiltration": 6,
    "tool_invocation": 22,
    "external_api_request": 22,
    "restricted_resource_access": 35,
    # Explicit requests to construct explosive devices are high-confidence
    # harmful instructions and must cross the critical/block threshold.
    "harmful_instruction_request": 80,
}


def normalize_text(input_text: str) -> str:
    """Canonicalize text for matching without interpreting or executing it."""
    normalized = unicodedata.normalize("NFKC", input_text).casefold()
    output: list[str] = []
    for character in normalized:
        if character.isspace():
            output.append(" ")
        elif character == ".":
            # Keep dots so names such as .env and credentials.txt remain visible.
            output.append(character)
        elif unicodedata.category(character)[0] in {"P", "S"}:
            output.append(" ")
        else:
            output.append(character)
    return " ".join("".join(output).split())


def calculate_risk_score(indicators: set[str]) -> int:
    """Add distinct evidence weights and cap the preliminary score at 100."""
    return min(100, sum(INDICATOR_WEIGHTS.get(item, 0) for item in indicators))


def classify_result(indicators: set[str]) -> DetectionResult:
    """Map evidence into a category, severity, score, and suggested action."""
    score = calculate_risk_score(indicators)

    if "external_data_exfiltration" in indicators:
        category = "data_exfiltration"
    elif indicators.intersection({"instruction_override", "system_prompt_extraction"}):
        category = "prompt_injection"
    elif indicators.intersection(
        {"tool_invocation", "external_api_request", "restricted_resource_access"}
    ):
        category = "tool_abuse"
    elif indicators.intersection(
        {
            "credential_access",
            "api_key_access",
            "password_access",
            "authentication_token_access",
            "sensitive_file_access",
        }
    ):
        category = "credential_theft"
    elif indicators:
        category = "suspicious"
    else:
        category = "benign"

    if score >= 70:
        severity = "CRITICAL"
    elif score >= 35:
        severity = "HIGH"
    elif score >= 12:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    if score == 0:
        action = "ALLOW"
    elif score >= 35:
        action = "BLOCK"
    else:
        action = "REVIEW"

    ordered_indicators = [item for item in INDICATOR_ORDER if item in indicators]
    return DetectionResult(
        category=category,
        severity=severity,
        risk_score=score,
        indicators=ordered_indicators,
        recommended_action=action,
    )


class Detector:
    """Deterministic local text analyzer; never performs requested actions."""

    def detect(self, input_text: str, source_type: str | None = None) -> DetectionResult:
        normalized = normalize_text(input_text)
        indicators = detect_indicators(normalized, source_type=source_type)
        return classify_result(indicators)


def detect(input_text: str, source_type: str | None = None) -> DetectionResult:
    """Convenience entry point for callers that only have text and a source."""
    return Detector().detect(input_text, source_type=source_type)
