"""ML scoring service: rule engine in, ranking score out (Stage 8).

No genuine labeled data exists in this repository yet (analyst labels arrive
with Stage 14, seeded demo data with Stage 15). Without real labels the
acceptance criterion "model beats the rules-only baseline" cannot be claimed
for production; this service therefore reports ``no_model`` until a model is
trained, and training results are explicitly marked as unvalidated for
production use. Stage 6 exclusion decisions always outrank ML scores.
"""

from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from risk_radar.ml.baseline import baseline_score_from_features, ranking_auc
from risk_radar.ml.features import FEATURE_NAMES, extract_features, vectorize
from risk_radar.ml.model import RuleScoreModel
from risk_radar.rules.engine import RuleEvaluation

ModelStatus = Literal[
    "scored",
    "no_model",
    "model_unavailable",
    "excluded_verified_official",
    "routed_to_verification",
    "failed_closed",
]

_SCORE_SEMANTICS = "model output for ranking only; NOT a calibrated probability of maliciousness"

_NON_EVALUATED_LIMITATIONS = {
    "excluded_verified_official": [
        "verified official asset excluded by Stage 6; ML scoring is not applied"
    ],
    "routed_to_verification": [
        "unverified identity held for verification by Stage 6; ML scoring is not applied"
    ],
    "failed_closed": ["gate decision unavailable: no ML score was produced (fail closed)"],
}


class MLScoreResult(BaseModel):
    """Structured ML output for one candidate."""

    schema_version: str = "1.0"
    model_status: ModelStatus
    model_id: str | None = None
    candidate_ref: str
    model_score: float | None = Field(default=None, ge=0, le=1)
    score_semantics: str = _SCORE_SEMANTICS
    feature_summary: dict[str, float] = Field(default_factory=dict)
    alert_eligible: bool = False
    limitations: list[str] = Field(default_factory=list)
    rule_evaluation: RuleEvaluation


class DatasetRow(BaseModel):
    """One labeled feature row supplied to training."""

    features: dict[str, float] = Field(default_factory=dict)
    label: int = Field(ge=0, le=1)


class TrainingResult(BaseModel):
    """Outcome of one training run, including held-out metrics."""

    status: Literal["trained", "failed"]
    model_id: str | None = None
    n_samples: int
    n_classes: int
    holdout_size: int = 0
    holdout_baseline_auc: float | None = None
    holdout_model_auc: float | None = None
    error: str | None = None
    limitations: list[str] = Field(
        default_factory=lambda: [
            "metrics come from the supplied dataset; production performance "
            "requires genuine analyst labels (Stage 14) and stays unvalidated"
        ]
    )


class MLService:
    """Score gate-eligible candidates and train the ranking model."""

    def __init__(self, model_path: str | Path | None = None) -> None:
        self._model: RuleScoreModel | None = None
        self._model_path = Path(model_path) if model_path else None

    def _load_persisted(self) -> str | None:
        """Try to load a persisted model; return an error reason on failure."""
        if self._model is not None or self._model_path is None:
            return None
        try:
            self._model = RuleScoreModel.load(self._model_path)
        except FileNotFoundError:
            return "model file not found"
        except Exception as exc:  # noqa: BLE001 - report any load failure honestly
            return f"model file could not be loaded ({exc.__class__.__name__})"
        return None

    def score(self, candidate_ref: str, rule_evaluation: RuleEvaluation) -> MLScoreResult:
        """Score a candidate without ever overriding the Stage 6 gate."""
        ref = candidate_ref[:255]
        if rule_evaluation.status != "evaluated":
            status: ModelStatus = rule_evaluation.status  # type: ignore[assignment]
            return MLScoreResult(
                model_status=status,
                candidate_ref=ref,
                alert_eligible=False,
                limitations=list(_NON_EVALUATED_LIMITATIONS.get(status, [])),
                rule_evaluation=rule_evaluation,
            )

        features = extract_features(rule_evaluation)
        eligible = True  # not_matched candidates may proceed to detection
        if self._model is None:
            load_error = self._load_persisted()
            if load_error is not None:
                return MLScoreResult(
                    model_status="model_unavailable",
                    candidate_ref=ref,
                    feature_summary=features,
                    alert_eligible=eligible,
                    limitations=[f"model unavailable: {load_error}"],
                    rule_evaluation=rule_evaluation,
                )
        if self._model is None or not self._model.is_trained:
            return MLScoreResult(
                model_status="no_model",
                candidate_ref=ref,
                feature_summary=features,
                alert_eligible=eligible,
                limitations=[
                    "no trained model available: prioritization falls back to "
                    "rule findings only until Stage 14/15 labels exist"
                ],
                rule_evaluation=rule_evaluation,
            )

        try:
            score_value = self._model.probabilities([vectorize(features)])[0]
        except Exception as exc:  # noqa: BLE001 - never crash the pipeline on scoring
            return MLScoreResult(
                model_status="model_unavailable",
                candidate_ref=ref,
                feature_summary=features,
                alert_eligible=eligible,
                limitations=[f"scoring failed ({exc.__class__.__name__})"],
                rule_evaluation=rule_evaluation,
            )
        return MLScoreResult(
            model_status="scored",
            model_id=self._model.model_id,
            candidate_ref=ref,
            model_score=score_value,
            feature_summary=features,
            alert_eligible=eligible,
            rule_evaluation=rule_evaluation,
        )

    def train(self, dataset: Sequence[DatasetRow]) -> TrainingResult:
        """Train on labeled feature rows with a reproducible held-out split."""
        rows = [vectorize(row.features) for row in dataset]
        labels = [row.label for row in dataset]
        n_classes = len(set(labels))
        class_counts = {label: labels.count(label) for label in set(labels)}
        if len(rows) < 10 or n_classes < 2 or min(class_counts.values()) < 4:
            return TrainingResult(
                status="failed",
                n_samples=len(rows),
                n_classes=n_classes,
                error=(
                    "insufficient training data: need at least 10 samples with "
                    "both classes and at least 4 samples per class"
                ),
            )

        from sklearn.model_selection import train_test_split

        x_train, x_test, y_train, y_test = train_test_split(
            rows, labels, test_size=0.3, random_state=42, stratify=labels
        )
        model = RuleScoreModel()
        model.fit(x_train, y_train)
        model_scores = model.probabilities(x_test)
        baseline_scores = [
            baseline_score_from_features(dict(zip(FEATURE_NAMES, row, strict=True)))
            for row in x_test
        ]
        try:
            baseline_auc = ranking_auc(y_test, baseline_scores)
            model_auc = ranking_auc(y_test, model_scores)
        except ValueError as exc:
            return TrainingResult(
                status="failed",
                n_samples=len(rows),
                n_classes=n_classes,
                error=f"metric could not be computed ({exc})",
            )

        self._model = model
        if self._model_path is not None:
            model.save(self._model_path)
        return TrainingResult(
            status="trained",
            model_id=model.model_id,
            n_samples=len(rows),
            n_classes=n_classes,
            holdout_size=len(y_test),
            holdout_baseline_auc=baseline_auc,
            holdout_model_auc=model_auc,
        )
