"""Feature extraction from rule evaluations (Stage 8).

Only prediction-time information is used: matched rule findings, their
severities and confidences, evidence references and rule skip/no-match counts.
"""

from risk_radar.rules.engine import RuleEvaluation

FEATURE_NAMES = [
    "n_matched",
    "n_critical",
    "n_high",
    "n_medium",
    "n_low",
    "n_informational",
    "has_lookalike",
    "has_username_similarity",
    "has_ip_host",
    "has_url_structure",
    "has_new_domain",
    "has_logo_mismatch",
    "max_confidence",
    "mean_confidence",
    "n_evidence_refs",
    "n_skipped",
    "n_not_matched",
]

_RULE_FLAGS = {
    "lookalike_domain": "has_lookalike",
    "username_similarity": "has_username_similarity",
    "ip_host": "has_ip_host",
    "suspicious_url_structure": "has_url_structure",
    "newly_registered_domain": "has_new_domain",
    "logo_publisher_mismatch": "has_logo_mismatch",
}


def extract_features(evaluation: RuleEvaluation) -> dict[str, float]:
    """Convert one rule evaluation into a fixed-order numeric feature vector."""
    features = {name: 0.0 for name in FEATURE_NAMES}
    confidences: list[float] = []
    for finding in evaluation.findings:
        features["n_matched"] += 1.0
        severity_key = f"n_{finding.severity}"
        if severity_key in features:
            features[severity_key] += 1.0
        flag = _RULE_FLAGS.get(finding.rule_id)
        if flag is not None:
            features[flag] = 1.0
        if finding.confidence is not None:
            confidences.append(finding.confidence)
        features["n_evidence_refs"] += float(len(finding.evidence_refs))
    if confidences:
        features["max_confidence"] = max(confidences)
        features["mean_confidence"] = sum(confidences) / len(confidences)
    features["n_skipped"] = float(len(evaluation.skipped))
    features["n_not_matched"] = float(len(evaluation.not_matched))
    return features


def vectorize(features: dict[str, float]) -> list[float]:
    """Return the fixed-order numeric row for a feature dict (missing → 0)."""
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]
