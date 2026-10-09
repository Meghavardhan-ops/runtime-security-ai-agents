"""Tests for redacted, deterministic DLP scans and policy integration."""

import logging

import pytest

from backend.core.security_service import SecurityService
from backend.policy.dlp import DLPEngine


@pytest.fixture
def engine() -> DLPEngine:
    return DLPEngine()


def test_clean_text_has_no_sensitive_pattern(engine: DLPEngine) -> None:
    result = engine.scan("Quarterly planning notes contain no contact details.")

    assert result.scan_status == "scanned"
    assert result.data_type == "unclassified"
    assert result.classification == "no_pattern_detected"
    assert result.indicators == ()
    assert result.contains_sensitive_data is False
    assert result.severity == "NONE"


def test_detects_email_address(engine: DLPEngine) -> None:
    result = engine.scan("Contact: alex@example.test")

    assert "email" in result.indicators
    assert result.data_type == "confidential"
    assert result.severity == "MEDIUM"


def test_detects_phone_number(engine: DLPEngine) -> None:
    result = engine.scan("Call the test line at +1 (202) 555-0123.")

    assert "phone" in result.indicators
    assert result.contains_sensitive_data is True


@pytest.mark.parametrize(
    ("content", "indicator"),
    [
        ("api_key=TEST_ONLY_FAKE_TOKEN", "api_key"),
        ("Authorization: Bearer TEST_ONLY_FAKE_BEARER_TOKEN", "bearer_token"),
        ("password=TEST_ONLY_FAKE_PASSWORD", "password"),
        ("secret=TEST_ONLY_FAKE_SECRET", "secret"),
        (
            "-----BEGIN PRIVATE KEY-----\n"
            "TEST_ONLY_FAKE_PRIVATE_KEY_MATERIAL\n"
            "-----END PRIVATE KEY-----",
            "private_key",
        ),
        (
            "TEST_ONLY_FAKE_AWS_ACCESS_KEY=AKIA0000000000000000",
            "cloud_credential",
        ),
        (
            "aws_secret_access_key=TESTONLYFAKECLOUDSECRETVALUE",
            "cloud_credential",
        ),
        ("Google key: AIzaTEST_ONLY_FAKE_TOKEN", "api_key"),
    ],
)
def test_detects_sensitive_patterns(
    engine: DLPEngine, content: str, indicator: str
) -> None:
    result = engine.scan(content)

    assert indicator in result.indicators
    assert result.contains_sensitive_data is True
    assert result.severity == "HIGH"


def test_returns_multiple_indicator_names_without_secret_values(
    engine: DLPEngine,
) -> None:
    fake_token = "TEST_ONLY_FAKE_TOKEN"
    content = (
        f"api_key={fake_token}; email=alex@example.test; "
        "phone=+1 (202) 555-0123"
    )

    result = engine.scan(content)
    serialized = result.model_dump_json()

    assert set(result.indicators) == {"api_key", "email", "phone"}
    assert fake_token not in serialized
    assert "alex@example.test" not in serialized
    assert "555-0123" not in serialized


def test_empty_input_is_a_safe_completed_scan(engine: DLPEngine) -> None:
    result = engine.scan("")

    assert result.scan_status == "scanned"
    assert result.contains_sensitive_data is False
    assert result.indicators == ()


def test_repeated_scans_are_deterministic(engine: DLPEngine) -> None:
    content = "api_key=TEST_ONLY_FAKE_TOKEN and alex@example.test"

    assert engine.scan(content) == engine.scan(content)


def test_large_input_is_not_truncated_or_partially_scanned(engine: DLPEngine) -> None:
    result = engine.scan("ordinary text " * (engine._MAX_CONTENT_BYTES // 10))

    assert result.scan_status == "too_large"
    assert result.data_type == "unknown"
    assert result.contains_sensitive_data is None
    assert result.indicators == ()


@pytest.mark.parametrize("content", [None, 42, {"text": "not a string"}, ["text"]])
def test_malformed_input_fails_safely(engine: DLPEngine, content: object) -> None:
    result = engine.scan(content)

    assert result.scan_status == "invalid_input"
    assert result.data_type == "unknown"
    assert result.contains_sensitive_data is None
    assert result.indicators == ()


def test_scan_does_not_log_raw_content(
    engine: DLPEngine, caplog: pytest.LogCaptureFixture
) -> None:
    fake_secret = "TEST_ONLY_FAKE_SECRET_VALUE"
    with caplog.at_level(logging.DEBUG):
        engine.scan(f"secret={fake_secret}")

    assert fake_secret not in caplog.text


def test_url_like_text_is_not_contacted(
    engine: DLPEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    import socket

    def fail_if_network_is_used(*args: object, **kwargs: object) -> None:
        pytest.fail("DLP scan attempted network access")

    monkeypatch.setattr(socket, "create_connection", fail_if_network_is_used)
    result = engine.scan("Reference: https://example.test/path")

    assert result.scan_status == "scanned"
    assert result.indicators == ()


def test_dlp_result_is_not_an_authorization_decision(engine: DLPEngine) -> None:
    result = engine.scan("normal text")

    assert not hasattr(result, "allowed")
    assert not hasattr(result, "action")
    assert not hasattr(engine, "authorize")


def test_sensitive_scan_elevates_label_before_policy_check() -> None:
    service = SecurityService()

    scan, decision = service.check_data_with_content(
        "public", "external", "api_key=TEST_ONLY_FAKE_TOKEN"
    )

    assert scan.data_type == "confidential"
    assert "api_key" in scan.indicators
    assert decision.action == "BLOCK"
    assert decision.allowed is False


def test_no_pattern_match_does_not_certify_external_content_as_public() -> None:
    service = SecurityService()

    scan, decision = service.check_data_with_content(
        "public", "external", "Ordinary text with no detected patterns."
    )

    assert scan.classification == "no_pattern_detected"
    assert scan.data_type == "unclassified"
    assert decision.action == "BLOCK"
    assert decision.allowed is False


def test_no_pattern_match_does_not_certify_internal_content_from_caller_label() -> None:
    service = SecurityService()
    content = "Internal compensation table: employee A earns 250000 per year."

    scan, decision = service.check_data_with_content("public", "internal", content)

    assert scan.classification == "no_pattern_detected"
    assert decision.action == "REVIEW"
    assert decision.allowed is False
    event = service.audit_logger.events()[0]
    assert event.policy_decision == "ALLOW"
    assert event.recommended_action == "REVIEW"
    assert event.status == "review"
    assert content not in str(scan.model_dump())
    assert content not in str(event.model_dump())


def test_policy_engine_decides_after_dlp_classification() -> None:
    service = SecurityService()

    scan, decision = service.check_data_with_content(
        "public", "internal", "api_key=TEST_ONLY_FAKE_TOKEN"
    )

    assert scan.data_type == "confidential"
    assert decision.action == "REVIEW"
    assert decision.allowed is False


def test_sensitive_content_is_not_written_to_audit_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake_secret = "TEST_ONLY_FAKE_TOKEN"
    service = SecurityService()
    with caplog.at_level(logging.INFO, logger="backend.monitor.audit_logger"):
        service.check_data_with_content(
            "public", "external", f"api_key={fake_secret}"
        )

    assert fake_secret not in caplog.text


def test_labels_only_external_check_is_not_treated_as_a_dlp_scan() -> None:
    decision = SecurityService().check_data("public", "external")

    assert decision.action == "BLOCK"
    assert decision.allowed is False


def test_unscannable_content_fails_closed_through_policy() -> None:
    service = SecurityService()

    scan, decision = service.check_data_with_content(
        "public", "external", "x" * (DLPEngine._MAX_CONTENT_BYTES + 1)
    )

    assert scan.scan_status == "too_large"
    assert decision.action == "BLOCK"
    assert decision.allowed is False
