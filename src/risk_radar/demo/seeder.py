"""Repeatable, idempotent demo-data seeder (Stage 15).

Populates official brand profiles, brand assets, simulated user submissions,
triaged cases across workflow states (open, in_review, closed), and Stage 14
human reviews. All seeded entities are explicitly marked as synthetic.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from risk_radar.db.models import (
    AssetType,
    Brand,
    BrandAsset,
    Case,
    CaseEvent,
    CaseStatus,
    HumanReview,
    ReviewVerdict,
    Submission,
    SubmissionType,
)
from risk_radar.ml.features import extract_features
from risk_radar.rules.engine import RuleEngine

SYNTHETIC_PROVENANCE = {
    "dataset": "demo_synthetic_v1",
    "is_synthetic": True,
    "disclaimer": "Synthetic demo data generated for triage simulation.",
}


class DemoSeedSummary(BaseModel):
    """Execution summary of the idempotent demo seeding run."""

    is_synthetic: bool = True
    disclaimer: str = (
        "All seeded entities are synthetic demo data for triage demonstration purposes."
    )
    brands_created: int = 0
    assets_created: int = 0
    submissions_created: int = 0
    cases_created: int = 0
    reviews_created: int = 0
    details: dict[str, Any] = Field(default_factory=dict)


def seed_demo_data(db: Session) -> DemoSeedSummary:
    """Idempotently seed official brand profiles, submissions, cases, and reviews."""
    summary = DemoSeedSummary()

    # 1. Seed Official Brands
    brand_defs = [
        {
            "name": "PayPal",
            "assets": [
                {"type": AssetType.DOMAIN, "value": "paypal.com", "verified": True},
                {"type": AssetType.DOMAIN, "value": "paypal-objects.com", "verified": True},
                {"type": AssetType.ACCOUNT, "value": "paypal", "verified": True},
                {"type": AssetType.NAME, "value": "PayPal", "verified": True},
            ],
        },
        {
            "name": "Microsoft",
            "assets": [
                {"type": AssetType.DOMAIN, "value": "microsoft.com", "verified": True},
                {"type": AssetType.DOMAIN, "value": "live.com", "verified": True},
                {"type": AssetType.ACCOUNT, "value": "microsoft", "verified": True},
            ],
        },
        {
            "name": "Acme Bank",
            "assets": [
                {"type": AssetType.DOMAIN, "value": "acmebank.com", "verified": True},
                {"type": AssetType.ACCOUNT, "value": "acmebank", "verified": True},
            ],
        },
    ]

    brand_map: dict[str, Brand] = {}
    for b_def in brand_defs:
        brand = db.scalar(select(Brand).where(Brand.name == b_def["name"]))
        if brand is None:
            brand = Brand(name=b_def["name"])
            db.add(brand)
            db.flush()
            summary.brands_created += 1
        brand_map[b_def["name"]] = brand

        for a_def in b_def["assets"]:
            existing_asset = db.scalar(
                select(BrandAsset).where(
                    BrandAsset.brand_id == brand.id,
                    BrandAsset.asset_type == a_def["type"],
                    BrandAsset.value == a_def["value"],
                )
            )
            if existing_asset is None:
                asset = BrandAsset(
                    brand_id=brand.id,
                    asset_type=a_def["type"],
                    value=a_def["value"],
                    verified=a_def["verified"],
                )
                db.add(asset)
                db.flush()
                summary.assets_created += 1

    # 2. Seed Raw Submissions
    sub_defs = [
        {
            "type": SubmissionType.URL,
            "source": "discovery:urlhaus",
            "content": "https://paypa1-security-update.com/login",
            "brand": "PayPal",
        },
        {
            "type": SubmissionType.URL,
            "source": "user",
            "content": "https://paypal.com/signin",
            "brand": "PayPal",
        },
        {
            "type": SubmissionType.URL,
            "source": "discovery:openphish",
            "content": "https://microsoft-login-verify-account.com",
            "brand": "Microsoft",
        },
        {
            "type": SubmissionType.URL,
            "source": "user",
            "content": "https://acme-bank-update-alert.net/login",
            "brand": "Acme Bank",
        },
        {
            "type": SubmissionType.SOCIAL_PROFILE,
            "source": "user",
            "content": "@paypa1_support",
            "brand": "PayPal",
        },
        {
            "type": SubmissionType.MESSAGE,
            "source": "user",
            "content": "Urgent: Your PayPal account is locked. Verify at https://paypa1-security-update.com/login",
            "brand": "PayPal",
        },
    ]

    for s_def in sub_defs:
        content_hash = hashlib.sha256(s_def["content"].encode()).hexdigest()
        existing_sub = db.scalar(select(Submission).where(Submission.content_hash == content_hash))
        if existing_sub is None:
            brand = brand_map.get(s_def["brand"])
            sub = Submission(
                submission_type=s_def["type"],
                source=s_def["source"],
                content=s_def["content"],
                content_hash=content_hash,
                brand_id=brand.id if brand else None,
            )
            db.add(sub)
            db.flush()
            summary.submissions_created += 1

    # 3. Seed Cases with realistic triage states
    case_defs = [
        {
            "title": "PayPal Credential Harvester on Typosquat Domain",
            "target": "https://paypa1-security-update.com/login",
            "gate_outcome": "not_matched",
            "alert_eligible": True,
            "status": CaseStatus.IN_REVIEW,
            "notes": [
                "Automated discovery hit via URLhaus feed.",
                "Typosquatting detected: 'paypa1' target mimicking 'paypal.com'.",
            ],
            "review": {
                "verdict": ReviewVerdict.MALICIOUS,
                "reason": (
                    "Confirmed credential harvester mimicking official PayPal login with "
                    "homoglyph '1'."
                ),
                "analyst": "security_analyst_1",
                "label": 1,
            },
        },
        {
            "title": "Acme Bank Fake Account Verification Portal",
            "target": "https://acme-bank-update-alert.net/login",
            "gate_outcome": "not_matched",
            "alert_eligible": True,
            "status": CaseStatus.OPEN,
            "notes": [
                "User-submitted suspicious SMS link targeting Acme Bank customers.",
            ],
            "review": None,
        },
        {
            "title": "Corporate Login Verification (Legitimate Submission)",
            "target": "https://paypal.com/signin",
            "gate_outcome": "verified_official",
            "alert_eligible": False,
            "status": CaseStatus.CLOSED,
            "notes": [
                "User submitted official login URL for safety verification.",
                "Excluded by Stage 6 gate as verified official asset.",
            ],
            "review": {
                "verdict": ReviewVerdict.BENIGN,
                "reason": "Host matches verified official domain paypal.com without deception.",
                "analyst": "security_analyst_1",
                "label": 0,
            },
        },
    ]

    for c_def in case_defs:
        existing_case = db.scalar(select(Case).where(Case.target == c_def["target"]))
        if existing_case is None:
            case = Case(
                title=c_def["title"],
                target=c_def["target"],
                status=c_def["status"],
                gate_outcome=c_def["gate_outcome"],
                alert_eligible=c_def["alert_eligible"],
                snapshot=json.dumps({"provenance": SYNTHETIC_PROVENANCE}),
            )
            db.add(case)
            db.flush()
            summary.cases_created += 1

            # Add case events
            db.add(
                CaseEvent(
                    case_id=case.id,
                    event_type="status_change",
                    note=f"case opened; gate outcome: {c_def['gate_outcome']}",
                    actor="system",
                )
            )
            for note in c_def["notes"]:
                db.add(
                    CaseEvent(
                        case_id=case.id,
                        event_type="note",
                        note=note,
                        actor="analyst",
                    )
                )

            # 4. Seed Human Review (Stage 14) if defined
            r_def = c_def["review"]
            if r_def:
                features_json = None
                try:
                    rule_eval = RuleEngine().evaluate(db=db, target=case.target)
                    feats = extract_features(rule_eval)
                    features_json = json.dumps(feats)
                except Exception:
                    features_json = None

                review = HumanReview(
                    case_id=case.id,
                    target=case.target,
                    verdict=r_def["verdict"],
                    reason=r_def["reason"],
                    analyst=r_def["analyst"],
                    tags=json.dumps(["demo", "synthetic"]),
                    features_json=features_json,
                    label=r_def["label"],
                )
                db.add(review)
                db.flush()
                summary.reviews_created += 1
                db.add(
                    CaseEvent(
                        case_id=case.id,
                        event_type="decision",
                        note=f"Human review: {r_def['verdict'].upper()}. Reason: {r_def['reason']}",
                        actor=r_def["analyst"],
                    )
                )

    db.commit()
    summary.details = {
        "timestamp": datetime.now(UTC).isoformat(),
        "total_brands": db.scalar(select(Brand).count())
        if hasattr(select(Brand), "count")
        else len(list(db.scalars(select(Brand)).all())),
        "total_cases": len(list(db.scalars(select(Case)).all())),
        "total_reviews": len(list(db.scalars(select(HumanReview)).all())),
    }
    return summary


if __name__ == "__main__":
    from risk_radar.db.session import SessionLocal, init_db

    init_db()
    with SessionLocal() as session:
        res = seed_demo_data(session)
        print(f"Seeding completed successfully: {res.model_dump_json(indent=2)}")
