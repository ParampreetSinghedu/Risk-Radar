"""Rules-only baseline and evaluation metric (Stage 8).

The baseline scores a candidate purely from deterministic rule output:
the severity-weighted sum of matched findings
(critical=4, high=3, medium=2, low=1, informational=0.5).
The shared metric is ROC-AUC on a held-out split; a constant-score edge case
cannot produce a meaningful ranking and is reported as 0.5.
"""

from collections.abc import Mapping, Sequence

SEVERITY_WEIGHTS = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
    "informational": 0.5,
}


def baseline_score_from_features(features: Mapping[str, float]) -> float:
    """Severity-weighted baseline score from extracted features."""
    return sum(
        float(features.get(f"n_{severity}", 0.0)) * weight
        for severity, weight in SEVERITY_WEIGHTS.items()
    )


def ranking_auc(y_true: Sequence[int], scores: Sequence[float]) -> float:
    """ROC-AUC ranking metric; constant scores yield 0.5 by definition."""
    if len(set(y_true)) < 2 or len(set(scores)) == 1:
        return 0.5
    from sklearn.metrics import roc_auc_score

    return float(roc_auc_score(list(y_true), list(scores)))
