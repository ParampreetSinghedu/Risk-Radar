"""Tests for Stage 15 Demo Data Seeding."""

from fastapi.testclient import TestClient


def test_seed_demo_data_endpoint(client: TestClient) -> None:
    """The demo seeding endpoint must populate synthetic brands, cases, and reviews."""
    resp = client.post("/api/v1/demo/seed")
    assert resp.status_code == 200
    data = resp.json()

    assert data["is_synthetic"] is True
    assert "synthetic demo data" in data["disclaimer"].lower()
    assert data["brands_created"] >= 3
    assert data["cases_created"] >= 3
    assert data["reviews_created"] >= 2


def test_demo_seeder_is_idempotent(client: TestClient) -> None:
    """Running the demo seeder multiple times must not crash or duplicate unique constraints."""
    first_resp = client.post("/api/v1/demo/seed")
    assert first_resp.status_code == 200

    second_resp = client.post("/api/v1/demo/seed")
    assert second_resp.status_code == 200
    second_data = second_resp.json()
    assert second_data["is_synthetic"] is True


def test_seeded_data_populates_dashboard_and_cases(client: TestClient) -> None:
    """Seeded demo cases must reflect immediately in dashboard metrics and case listings."""
    client.post("/api/v1/demo/seed")

    dash_resp = client.get("/api/v1/dashboard")
    assert dash_resp.status_code == 200
    dash = dash_resp.json()

    assert dash["total_cases"] >= 3
    assert dash["open_cases"] >= 1
    assert dash["in_review_cases"] >= 1
    assert dash["closed_cases"] >= 1
    assert len(dash["recent_cases"]) >= 3

    cases_resp = client.get("/api/v1/cases")
    assert cases_resp.status_code == 200
    assert len(cases_resp.json()) >= 3
