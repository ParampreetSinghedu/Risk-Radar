"""Lightweight logistic regression over rule features (Stage 8)."""

import hashlib
from pathlib import Path
from typing import Any

import joblib
from sklearn.linear_model import LogisticRegression

from risk_radar.ml.features import FEATURE_NAMES


class RuleScoreModel:
    """Interpretable linear model producing a ranking score in [0, 1]."""

    VERSION = "logreg-v1"

    def __init__(self) -> None:
        self.feature_names = list(FEATURE_NAMES)
        self._classifier: LogisticRegression | None = None

    def fit(self, rows: list[list[float]], labels: list[int]) -> None:
        """Train the classifier; callers must guarantee both classes exist."""
        self._classifier = LogisticRegression(max_iter=1000, random_state=42)
        self._classifier.fit(rows, labels)

    @property
    def is_trained(self) -> bool:
        return self._classifier is not None

    def probabilities(self, rows: list[list[float]]) -> list[float]:
        """Return ranking scores (NOT calibrated maliciousness probabilities)."""
        if self._classifier is None:
            raise RuntimeError("model is not trained")
        return [float(value) for value in self._classifier.predict_proba(rows)[:, 1]]

    @property
    def model_id(self) -> str:
        """Deterministic identifier derived from the version and coefficients."""
        if self._classifier is None:
            return f"{self.VERSION}:untrained"
        digest = hashlib.sha256(self._classifier.coef_.tobytes()).hexdigest()[:12]
        return f"{self.VERSION}:{digest}"

    def save(self, path: str | Path) -> None:
        """Persist the model to a joblib file."""
        joblib.dump(self._classifier, Path(path))

    @classmethod
    def load(cls, path: str | Path) -> "RuleScoreModel":
        """Load a persisted model; raises when the file is missing or invalid."""
        instance = cls()
        classifier: Any = joblib.load(Path(path))
        if not isinstance(classifier, LogisticRegression):
            raise ValueError("persisted object is not a LogisticRegression model")
        instance._classifier = classifier
        return instance
