"""Tests for Stage 8 ML engine: features, baseline, training, scoring."""

import numpy as np
from fastapi.testclient import TestClient

from risk_radar.ml.baseline import baseline_score_from_features, ranking_auc
from risk_radar.ml.features import FEATURE_NAMES, extract_features, vectorize
from risk_radar.ml.model import RuleScoreModel
from risk_radar.ml.service import DatasetRow, MLService
from risk_radar.rules.engine import RuleEvaluation


def _seed(client: TestClient) -> None:
    brand = client.post("/api/v1/brands", json={"name": "Acme"}).json()
    client.post(
        f"/api/v1/brands/{brand['id']}/assets",
        json={"asset_type": "domain", "value": "acme.example", "verified": True},
    )


def _synthetic_dataset(n: int = 120, seed: int = 7) -> list[DatasetRow]:
    """Deterministic synthetic rows exercising the pipeline end-to-end.

    Labels depend partly on severity-weighted rules and partly on
    confidence/evidence features the baseline cannot use, so a model trained
    on them beats the rules-only baseline on held-out data. This validates
    the pipeline mechanics only — it is NOT real detection performance
    (documented limitation; production labels arrive with Stage 14/15).
    """
    rng = np.random.default_rng(seed)
    rows: list[DatasetRow] = []
    for _ in range(n):
        n_medium = int(rng.integers(0, 3))
        n_high = int(rng.integers(0, 2))
        confidence = float(rng.uniform(0.5, 1.0))
        evidence = float(rng.uniform(0.0, 1.0))
        noise = float(rng.normal(0.0, 0.10))
        signal = 0.15 * ((2 * n_medium + 3 * n_high) / 5.0) + 0.50 * confidence + 0.35 * evidence
        label = int(signal + noise > 0.62)
        rows.append(
            DatasetRow(
                features={
                    "n_matched": float(n_medium + n_high),
                    "n_medium": float(n_medium),
                    "n_high": float(n_high),
                    "max_confidence": confidence,
                    "mean_confidence": confidence,
                    "n_evidence_refs": evidence * 2.0,
                },
                label=label,
            )
        )
    return rows


def test_feature_extraction_from_real_evaluation(client: TestClient) -> None:
    """Features reflect matched rules, severities and evidence references."""
    _seed(client)
    response = client.post("/api/v1/rules/evaluate", json={"target": "http://login.acme.example/"})
    evaluation = RuleEvaluation.model_validate(response.json())

    features = extract_features(evaluation)

    assert set(features) == set(FEATURE_NAMES)
    assert features["n_matched"] == 1.0
    assert features["has_lookalike"] == 1.0
    assert features["n_medium"] == 1.0
    assert features["n_evidence_refs"] >= 1.0
    assert features["n_skipped"] >= 1.0
    assert vectorize(features) == [features[name] for name in FEATURE_NAMES]


def test_feature_extraction_handles_empty_evaluation() -> None:
    """A benign evaluation yields an all-zero vector without crashing."""
    empty = RuleEvaluation(status="evaluated", candidate_ref="x")

    features = extract_features(empty)

    assert all(value == 0.0 for value in features.values())


def test_rules_only_baseline_and_metric() -> None:
    """Baseline is the documented severity-weighted sum; metric is ROC-AUC."""
    assert baseline_score_from_features({"n_high": 1, "n_medium": 2}) == 7.0
    assert baseline_score_from_features({}) == 0.0
    assert ranking_auc([0, 1], [0.1, 0.9]) == 1.0
    assert ranking_auc([0, 1], [0.9, 0.1]) == 0.0
    assert ranking_auc([1, 1], [0.2, 0.3]) == 0.5  # constant/one-class edge


def test_training_reports_holdout_baseline_and_model_metrics() -> None:
    """Training runs a stratified split and reports both metrics."""
    service = MLService()
    result = service.train(_synthetic_dataset())

    assert result.status == "trained"
    assert result.n_samples == 120
    assert result.n_classes == 2
    assert result.holdout_size == 36
    assert result.holdout_baseline_auc is not None
    assert result.holdout_model_auc is not None
    assert 0.0 <= result.holdout_baseline_auc <= 1.0
    assert 0.0 <= result.holdout_model_auc <= 1.0
    # Pipeline acceptance on the (synthetic) held-out set: model beats baseline.
    assert result.holdout_model_auc > result.holdout_baseline_auc
    assert any("unvalidated" in limitation for limitation in result.limitations)


def test_training_is_deterministic() -> None:
    """Same dataset → identical model id and metrics."""
    first = MLService().train(_synthetic_dataset())
    second = MLService().train(_synthetic_dataset())

    assert first.model_id == second.model_id
    assert first.holdout_model_auc == second.holdout_model_auc
    assert first.holdout_baseline_auc == second.holdout_baseline_auc


def test_insufficient_training_data_fails_cleanly() -> None:
    """Too few samples or a single class never train a model."""
    service = MLService()
    tiny = [DatasetRow(features={"n_matched": 1.0}, label=1)]
    result = service.train(tiny)

    assert result.status == "failed"
    assert result.model_id is None
    assert "insufficient training data" in (result.error or "")

    single_class = [DatasetRow(features={"n_matched": float(i)}, label=1) for i in range(12)]
    assert service.train(single_class).status == "failed"


def test_model_save_load_roundtrip(tmp_path) -> None:
    """Persisted models reload with identical scores; bad files are rejected."""
    rows = _synthetic_dataset()
    model = RuleScoreModel()
    model.fit([vectorize(r.features) for r in rows[:56]], [r.label for r in rows[:56]])
    probe = [vectorize(rows[70].features)]

    path = tmp_path / "model.joblib"
    model.save(path)
    loaded = RuleScoreModel.load(path)

    assert loaded.model_id == model.model_id
    assert loaded.probabilities(probe) == model.probabilities(probe)
    try:
        RuleScoreModel.load(tmp_path / "missing.joblib")
        raise AssertionError("expected FileNotFoundError")
    except FileNotFoundError:
        pass


def test_scoring_without_model_reports_no_model(client: TestClient) -> None:
    """Before any training, scoring is honest: no invented scores."""
    _seed(client)

    response = client.post("/api/v1/ml/score", json={"target": "http://login.acme.example/"})

    assert response.status_code == 200
    body = response.json()
    assert body["model_status"] == "no_model"
    assert body["model_score"] is None
    assert body["alert_eligible"] is True  # gate-eligible, just unscored
    assert body["feature_summary"]["has_lookalike"] == 1.0
    assert "NOT a calibrated probability" in body["score_semantics"]


def test_train_then_score_through_the_api(client: TestClient) -> None:
    """A model trained via the API is used for subsequent scoring."""
    _seed(client)
    dataset = [{"features": row.features, "label": row.label} for row in _synthetic_dataset()]

    train_response = client.post("/api/v1/ml/train", json={"dataset": dataset})
    assert train_response.status_code == 200
    assert train_response.json()["status"] == "trained"

    score = client.post("/api/v1/ml/score", json={"target": "http://freshlook.example/"})
    assert score.status_code == 200
    body = score.json()
    assert body["model_status"] == "scored"
    assert body["model_id"] and body["model_id"].startswith("logreg-v1")
    assert body["model_score"] is not None and 0.0 <= body["model_score"] <= 1.0
    assert body["alert_eligible"] is True
    assert body["rule_evaluation"]["status"] == "evaluated"

    again = client.post("/api/v1/ml/score", json={"target": "http://freshlook.example/"})
    assert again.json()["model_score"] == body["model_score"]  # deterministic


def test_verified_official_never_alert_eligible_through_ml(client: TestClient) -> None:
    """Stage 6 exclusion outranks ML: no score, no alert eligibility."""
    _seed(client)

    response = client.post(
        "/api/v1/ml/score",
        json={"target": "http://acme.example/", "alert_eligible": True},
    )

    body = response.json()
    assert body["model_status"] == "excluded_verified_official"
    assert body["model_score"] is None
    assert body["alert_eligible"] is False
    assert body["rule_evaluation"]["findings"] == []


def test_unverified_candidate_routed_not_scored(client: TestClient) -> None:
    """Unverified identities stay in verification regardless of ML."""
    brand = client.post("/api/v1/brands", json={"name": "Acme"}).json()
    client.post(
        f"/api/v1/brands/{brand['id']}/assets",
        json={"asset_type": "account", "value": "@acme", "verified": False},
    )

    response = client.post("/api/v1/ml/score", json={"target": "@acme"})

    body = response.json()
    assert body["model_status"] == "routed_to_verification"
    assert body["model_score"] is None
    assert body["alert_eligible"] is False


def test_missing_model_file_reports_unavailable(tmp_path) -> None:
    """A configured-but-missing model file degrades to an explicit status."""
    from risk_radar.rules.engine import RuleEvaluation as Evaluation

    service = MLService(model_path=tmp_path / "absent.joblib")
    result = service.score(
        candidate_ref="c1",
        rule_evaluation=Evaluation(status="evaluated", candidate_ref="c1"),
    )

    assert result.model_status == "model_unavailable"
    assert result.model_score is None
    assert any("not found" in limitation for limitation in result.limitations)


def test_invalid_ml_requests_rejected(client: TestClient) -> None:
    """Blank targets, malformed analysis and bad labels return 422."""
    assert client.post("/api/v1/ml/score", json={"target": ""}).status_code == 422
    assert (
        client.post(
            "/api/v1/ml/score",
            json={"target": "http://x.example/", "analysis": {"analyzer_type": "url"}},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/ml/train",
            json={"dataset": [{"features": {"n_matched": "not-a-number"}, "label": 1}]},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/ml/train",
            json={"dataset": [{"features": {}, "label": 7}]},
        ).status_code
        == 422
    )


def test_missing_features_default_to_zero_in_training() -> None:
    """Rows with sparse or unknown feature dicts are handled via vectorize."""
    service = MLService()
    rows = [
        DatasetRow(features={"n_matched": 1.0} if i % 2 else {}, label=i % 2) for i in range(20)
    ]

    result = service.train(rows)

    assert result.status in {"trained", "failed"}  # handled without exceptions
    assert result.n_samples == 20
