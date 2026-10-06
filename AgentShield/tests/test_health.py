"""Tests for the service health endpoint."""

from fastapi.testclient import TestClient

from backend.core.config import settings
from backend.main import app

client = TestClient(app)


def test_health_returns_service_status() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": settings.service_name}
