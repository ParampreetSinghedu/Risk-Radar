"""Tests for Stage 15 Evaluation Benchmark."""

from fastapi.testclient import TestClient


def test_evaluation_benchmark_endpoint(client: TestClient) -> None:
    """Evaluation benchmark endpoint returns metrics and synthetic disclaimers."""
    resp = client.get("/api/v1/evaluation/benchmark?sample_limit=10")
    assert resp.status_code == 200
    data = resp.json()

    assert data["is_synthetic_benchmark"] is True
    assert data["calibrated_probability"] is False
    assert "synthetic evaluation dataset" in data["disclaimer"].lower()

    metrics = data["metrics"]
    assert metrics["total_samples"] == 10
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0
    assert metrics["avg_latency_ms"] >= 0.0

    assert isinstance(data["fired_rule_distribution"], dict)
    assert len(data["sample_evaluations"]) > 0


def test_evaluation_benchmark_full_run(client: TestClient) -> None:
    """Running full benchmark executes without errors and categorizes detections."""
    resp = client.get("/api/v1/evaluation/benchmark")
    assert resp.status_code == 200
    data = resp.json()

    metrics = data["metrics"]
    assert metrics["total_samples"] == 40
    assert metrics["malicious_ground_truth"] == 20
    assert metrics["benign_ground_truth"] == 20
    assert metrics["true_positives"] > 0
    assert metrics["true_negatives"] > 0
