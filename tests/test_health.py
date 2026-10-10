"""Tests for the scaffolded API health endpoint."""

from fastapi.testclient import TestClient

from risk_radar.main import app


def test_health_endpoint_returns_ok() -> None:
    """The versioned liveness route should return a stable healthy response."""
    with TestClient(app) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
