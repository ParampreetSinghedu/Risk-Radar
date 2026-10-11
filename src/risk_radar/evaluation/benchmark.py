"""Evaluation benchmark harness for Stage 15.

Evaluates gate decisions, rule detections, and risk classifications against
a reproducible synthetic evaluation dataset. All outputs explicitly declare
their synthetic benchmark status and avoid claiming calibrated real-world
probabilities.
"""

from __future__ import annotations

import time
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from risk_radar.rules.engine import RuleEngine

# 40 diverse benchmark test samples: 20 malicious (lookalike, IP, structure), 20 benign
BENCHMARK_SAMPLES: list[dict[str, Any]] = [
    # Malicious samples
    {"target": "https://paypa1-security-center.com/login", "label": 1, "brand": "PayPal"},
    {"target": "https://paypal-verify-billing-update.net/auth", "label": 1, "brand": "PayPal"},
    {"target": "https://192.168.1.100/paypal/login.php", "label": 1, "brand": "PayPal"},
    {
        "target": "https://microsoft-account-secure-reset.org/login",
        "label": 1,
        "brand": "Microsoft",
    },
    {"target": "https://micros0ft-support-desk.com", "label": 1, "brand": "Microsoft"},
    {"target": "https://acme-bank-online-alert.com/signin", "label": 1, "brand": "Acme Bank"},
    {"target": "https://acmebank-security-portal.net/verify", "label": 1, "brand": "Acme Bank"},
    {"target": "https://google-auth-verify-user.xyz/login", "label": 1, "brand": "Google"},
    {"target": "https://g00gle-accounts-security.net", "label": 1, "brand": "Google"},
    {"target": "https://apple-id-verify-payment.info/auth", "label": 1, "brand": "Apple"},
    {"target": "https://netflix-account-on-hold.com/login", "label": 1, "brand": "Netflix"},
    {"target": "https://amazon-order-confirmation-urgent.net", "label": 1, "brand": "Amazon"},
    {"target": "https://chase-bank-verify-pin.com/secure", "label": 1, "brand": "Chase"},
    {"target": "https://wellsfarg0-account-status.org/login", "label": 1, "brand": "Wells Fargo"},
    {
        "target": "https://bankofamerica-alert-center.net/auth",
        "label": 1,
        "brand": "Bank of America",
    },
    {"target": "https://10.0.0.1/auth/secure-login", "label": 1, "brand": None},
    {"target": "https://secure-login-update-service.cc/signin", "label": 1, "brand": None},
    {"target": "https://verify-identity-portal.biz/account", "label": 1, "brand": None},
    {"target": "https://paypa1.com/login", "label": 1, "brand": "PayPal"},
    {"target": "https://microsoft-office365-upgrade.com", "label": 1, "brand": "Microsoft"},
    # Benign samples
    {"target": "https://paypal.com/signin", "label": 0, "brand": "PayPal"},
    {"target": "https://paypal.com/myaccount/summary", "label": 0, "brand": "PayPal"},
    {"target": "https://paypal-objects.com/webstatic/icon.png", "label": 0, "brand": "PayPal"},
    {"target": "https://microsoft.com/en-us/windows", "label": 0, "brand": "Microsoft"},
    {"target": "https://live.com/login", "label": 0, "brand": "Microsoft"},
    {"target": "https://acmebank.com", "label": 0, "brand": "Acme Bank"},
    {"target": "https://acmebank.com/about-us", "label": 0, "brand": "Acme Bank"},
    {"target": "https://google.com/search?q=weather", "label": 0, "brand": "Google"},
    {"target": "https://github.com/torvalds/linux", "label": 0, "brand": None},
    {"target": "https://en.wikipedia.org/wiki/Computer_security", "label": 0, "brand": None},
    {"target": "https://stackoverflow.com/questions", "label": 0, "brand": None},
    {"target": "https://python.org/downloads", "label": 0, "brand": None},
    {"target": "https://fastapi.tiangolo.com/tutorial", "label": 0, "brand": None},
    {"target": "https://pydantic.dev/docs", "label": 0, "brand": None},
    {"target": "https://sqlalchemy.org/library", "label": 0, "brand": None},
    {"target": "https://alembic.sqlalchemy.org/en/latest", "label": 0, "brand": None},
    {"target": "https://developer.mozilla.org/en-US/docs/Web", "label": 0, "brand": None},
    {"target": "https://news.ycombinator.com", "label": 0, "brand": None},
    {"target": "https://archive.org/details/texts", "label": 0, "brand": None},
    {"target": "https://example.com/test-page", "label": 0, "brand": None},
]


class BenchmarkMetrics(BaseModel):
    """Calculated classification and latency metrics."""

    total_samples: int
    malicious_ground_truth: int
    benign_ground_truth: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    avg_latency_ms: float


class BenchmarkReport(BaseModel):
    """Audited evaluation report produced from the evaluation benchmark."""

    is_synthetic_benchmark: bool = True
    calibrated_probability: bool = False
    disclaimer: str = (
        "Benchmark evaluated on synthetic evaluation dataset for testing and "
        "demonstration only. Does not reflect calibrated real-world production distribution."
    )
    metrics: BenchmarkMetrics
    fired_rule_distribution: dict[str, int] = Field(default_factory=dict)
    sample_evaluations: list[dict[str, Any]] = Field(default_factory=list)


def run_benchmark(db: Session, sample_limit: int | None = None) -> BenchmarkReport:
    """Run detection pipeline against benchmark samples and compute evaluation metrics."""
    samples = BENCHMARK_SAMPLES[:sample_limit] if sample_limit else BENCHMARK_SAMPLES
    engine = RuleEngine()

    tp = fp = tn = fn = 0
    total_time = 0.0
    rule_counts: dict[str, int] = {}
    sample_records: list[dict[str, Any]] = []

    for s in samples:
        target = s["target"]
        ground_truth = s["label"]

        start_t = time.perf_counter()
        eval_result = engine.evaluate(db=db, target=target)
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        total_time += elapsed_ms

        fired_rules = [f.rule_id for f in eval_result.findings]
        for r_id in fired_rules:
            rule_counts[r_id] = rule_counts.get(r_id, 0) + 1

        # Prediction: positive if any non-informational rule fired and gate didn't exclude official
        gate_status = eval_result.gate_decision.outcome
        is_official = gate_status == "verified_official"

        if is_official:
            predicted = 0
        else:
            # Predicted malicious if any findings detected
            predicted = 1 if len(eval_result.findings) > 0 else 0

        if ground_truth == 1:
            if predicted == 1:
                tp += 1
            else:
                fn += 1
        elif ground_truth == 0:
            if predicted == 1:
                fp += 1
            else:
                tn += 1

        sample_records.append(
            {
                "target": target,
                "ground_truth": ground_truth,
                "predicted": predicted,
                "gate_outcome": gate_status,
                "fired_rules": fired_rules,
                "latency_ms": round(elapsed_ms, 2),
            }
        )

    total = len(samples)
    positives = sum(1 for s in samples if s["label"] == 1)
    negatives = sum(1 for s in samples if s["label"] == 0)

    accuracy = round((tp + tn) / total, 4) if total > 0 else 0.0
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = (
        round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0
    )
    avg_latency = round(total_time / total, 2) if total > 0 else 0.0

    metrics = BenchmarkMetrics(
        total_samples=total,
        malicious_ground_truth=positives,
        benign_ground_truth=negatives,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1_score=f1,
        avg_latency_ms=avg_latency,
    )

    return BenchmarkReport(
        metrics=metrics,
        fired_rule_distribution=rule_counts,
        sample_evaluations=sample_records[:10],  # sample preview
    )


if __name__ == "__main__":
    from risk_radar.db.session import SessionLocal, init_db

    init_db()
    with SessionLocal() as session:
        rep = run_benchmark(session)
        print(f"Benchmark Report:\n{rep.model_dump_json(indent=2)}")
