"""API and service tests for untrusted input normalization."""

import hashlib
import logging
from datetime import datetime, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from backend.core.config import settings
from backend.gateway.input_gateway import InputGateway, SecurityInputRequest
from backend.main import app

client = TestClient(app)
INPUTS_URL = "/api/v1/inputs"


def payload(
    source_type: str = "text",
    source_name: str = "sample.txt",
    content: str = "Example document",
    metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "source_type": source_type,
        "source_name": source_name,
        "content": content,
        "metadata": metadata or {},
    }


@pytest.mark.parametrize("source_type", ["text", "file", "email", "web", "api", "database"])
def test_accepts_each_allowed_source_type(source_type: str) -> None:
    response = client.post(INPUTS_URL, json=payload(source_type=source_type))

    assert response.status_code == 201
    assert response.json()["source_type"] == source_type
    assert response.json()["trusted"] is False


def test_rejects_invalid_source_type() -> None:
    response = client.post(INPUTS_URL, json=payload(source_type="ftp"))

    assert response.status_code == 422


def test_rejects_empty_content() -> None:
    response = client.post(INPUTS_URL, json=payload(content=" \r\n "))

    assert response.status_code == 422


def test_rejects_oversized_content() -> None:
    content = "x" * (settings.input_max_content_bytes + 1)

    response = client.post(INPUTS_URL, json=payload(content=content))

    assert response.status_code == 413


def test_rejects_oversized_source_name() -> None:
    source_name = "x" * (settings.input_max_source_name_length + 1)

    response = client.post(INPUTS_URL, json=payload(source_name=source_name))

    assert response.status_code == 413


def test_rejects_oversized_metadata() -> None:
    metadata = {"note": "x" * settings.input_max_metadata_bytes}

    response = client.post(INPUTS_URL, json=payload(metadata=metadata))

    assert response.status_code == 413


def test_rejects_missing_fields() -> None:
    response = client.post(INPUTS_URL, json={"source_type": "text"})

    assert response.status_code == 422


def test_rejects_caller_supplied_trusted_flag() -> None:
    request = payload()
    request["trusted"] = True

    response = client.post(INPUTS_URL, json=request)

    assert response.status_code == 422


def test_normalizes_and_hashes_content() -> None:
    source = "Cafe\u0301\r\nExample"
    normalized = "Café\nExample"
    response = client.post(INPUTS_URL, json=payload(content=source))

    assert response.status_code == 201
    assert response.json()["content"] == normalized
    assert response.json()["content_hash"] == hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


def test_generates_unique_ids_and_timestamp() -> None:
    first = client.post(INPUTS_URL, json=payload()).json()
    second = client.post(INPUTS_URL, json=payload()).json()

    assert UUID(first["id"]) != UUID(second["id"])
    received_at = datetime.fromisoformat(first["received_at"].replace("Z", "+00:00"))
    assert received_at.utcoffset() == timezone.utc.utcoffset(received_at)


def test_attaches_metadata_and_defaults_to_untrusted() -> None:
    metadata = {"filename": "invoice.txt"}
    response = client.post(
        INPUTS_URL,
        json=payload(source_type="file", source_name="invoice.txt", metadata=metadata),
    )

    assert response.status_code == 201
    assert response.json()["metadata"] == metadata
    assert response.json()["trusted"] is False


def test_sensitive_content_is_not_written_to_logs(caplog: pytest.LogCaptureFixture) -> None:
    secret_text = "SENSITIVE-CONTENT-DO-NOT-LOG"
    request = SecurityInputRequest.model_validate(payload(content=secret_text))

    with caplog.at_level(logging.INFO, logger="backend.gateway.input_gateway"):
        InputGateway().normalize(request)

    assert secret_text not in caplog.text
    assert "content_hash=" in caplog.text
    assert "content_size_bytes=" in caplog.text
