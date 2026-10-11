"""Tests for Stage 14 Human Review and Feedback Loop."""

from fastapi.testclient import TestClient


def test_record_review_with_mandatory_reason(client: TestClient) -> None:
    """An analyst review must be safely persisted with its mandatory justification."""
    resp = client.post(
        "/api/v1/review",
        json={
            "target": "https://paypa1-security-check.com/login",
            "verdict": "malicious",
            "reason": "Typosquat lookalike domain with homoglyph '1' targeting credential theft.",
            "analyst": "test_analyst",
            "tags": ["phishing", "credential_theft"],
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["verdict"] == "malicious"
    assert data["label"] == 1
    assert data["analyst"] == "test_analyst"
    assert "homoglyph" in data["reason"]
    assert data["has_features"] is True


def test_record_review_empty_or_too_short_reason_rejected(client: TestClient) -> None:
    """Review verdicts must reject empty, whitespace, or insufficiently reasoned submissions."""
    resp = client.post(
        "/api/v1/review",
        json={
            "target": "https://example.com",
            "verdict": "benign",
            "reason": "   ",
        },
    )
    assert resp.status_code == 422

    resp_short = client.post(
        "/api/v1/review",
        json={
            "target": "https://example.com",
            "verdict": "benign",
            "reason": "bad",
        },
    )
    assert resp_short.status_code == 422


def test_record_review_attached_to_case_updates_workflow(client: TestClient) -> None:
    """A review linked to a case updates status, appends decision, and persists verdict."""
    case_resp = client.post(
        "/api/v1/cases",
        json={
            "title": "Phishing Incident Review",
            "target": "https://fake-login-example.com",
        },
    )
    assert case_resp.status_code == 201
    case_id = case_resp.json()["id"]

    review_resp = client.post(
        "/api/v1/review",
        json={
            "case_id": case_id,
            "verdict": "malicious",
            "reason": "Confirmed fake login portal mimicking authentication flow.",
            "analyst": "lead_investigator",
        },
    )
    assert review_resp.status_code == 201

    updated_case = client.get(f"/api/v1/cases/{case_id}").json()
    assert updated_case["status"] == "closed"
    event_types = [e["event_type"] for e in updated_case["events"]]
    assert "decision" in event_types


def test_review_audit_history_and_feedback_labels(client: TestClient) -> None:
    """Audit trail must list all reviews, and feedback endpoint formats labels for ML."""
    client.post(
        "/api/v1/review",
        json={
            "target": "https://paypa1-update.com",
            "verdict": "malicious",
            "reason": "Homoglyph lookalike impersonation domain.",
            "analyst": "analyst_a",
        },
    )
    client.post(
        "/api/v1/review",
        json={
            "target": "https://paypal.com/signin",
            "verdict": "benign",
            "reason": "Official verified domain.",
            "analyst": "analyst_b",
        },
    )

    history_resp = client.get("/api/v1/review/history")
    assert history_resp.status_code == 200
    history = history_resp.json()
    assert len(history) >= 2

    feedback_resp = client.get("/api/v1/feedback/labels")
    assert feedback_resp.status_code == 200
    fb_data = feedback_resp.json()
    assert fb_data["count"] >= 2
    assert fb_data["usable_training_count"] >= 2

    labels = [item["label"] for item in fb_data["items"]]
    assert 1 in labels
    assert 0 in labels
