"""Human review and analyst feedback loop (Stage 14).

Analysts record definitive review verdicts with mandatory reasons.
Verdicts update case workflows, append audit events, and build a labeled
dataset for retraining the Stage 8 ML Engine.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from risk_radar.db.models import Case, CaseEvent, CaseStatus, HumanReview, ReviewVerdict
from risk_radar.db.session import get_db
from risk_radar.ml.features import extract_features, vectorize
from risk_radar.rules.engine import RuleEngine

router = APIRouter(tags=["review"])


class ReviewCreate(BaseModel):
    """Payload to record an audited human review verdict."""

    case_id: int | None = None
    target: str | None = Field(default=None, max_length=2048)
    verdict: Literal["malicious", "benign", "suspicious"]
    reason: str = Field(min_length=5, max_length=4000, description="Mandatory reason for verdict")
    analyst: str = Field(default="analyst", min_length=1, max_length=64)
    tags: list[str] | None = None


class ReviewResponse(BaseModel):
    """Audited review verdict record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int | None
    target: str
    verdict: str
    reason: str
    analyst: str
    tags: list[str] = Field(default_factory=list)
    label: int
    has_features: bool = False
    created_at: datetime


class FeedbackItem(BaseModel):
    """One labeled record for retraining or benchmark evaluation."""

    review_id: int
    case_id: int | None
    target: str
    verdict: str
    label: int
    reason: str
    analyst: str
    features: dict[str, float] | list[float] | None = None
    vector: list[float] | None = None
    created_at: datetime


class FeedbackLabelsResponse(BaseModel):
    """Retrieved feedback labels ready for model retraining."""

    count: int
    usable_training_count: int
    items: list[FeedbackItem] = Field(default_factory=list)


def _serialize_review(review: HumanReview) -> ReviewResponse:
    parsed_tags = []
    if review.tags:
        try:
            parsed_tags = json.loads(review.tags)
        except Exception:
            parsed_tags = [t.strip() for t in review.tags.split(",") if t.strip()]

    has_feats = bool(review.features_json)
    return ReviewResponse(
        id=review.id,
        case_id=review.case_id,
        target=review.target,
        verdict=review.verdict,
        reason=review.reason,
        analyst=review.analyst,
        tags=parsed_tags,
        label=review.label,
        has_features=has_feats,
        created_at=review.created_at,
    )


@router.post(
    "/review",
    response_model=ReviewResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record human review verdict",
)
def record_review(payload: ReviewCreate, db: Annotated[Session, Depends(get_db)]) -> ReviewResponse:
    """Record an analyst review with mandatory reasoning and feedback label."""
    if not payload.reason.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Mandatory reason cannot be empty or whitespace.",
        )

    case: Case | None = None
    target = (payload.target or "").strip()

    if payload.case_id is not None:
        case = db.get(Case, payload.case_id)
        if case is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case #{payload.case_id} not found.",
            )
        if not target:
            target = case.target.strip()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Target is required when not linking to an existing case.",
        )

    # Compute binary training label: 1 for confirmed malicious, 0 for benign/suspicious
    label = 1 if payload.verdict == ReviewVerdict.MALICIOUS else 0

    # Extract deterministic feature vector from rule engine for ML feedback loop
    features_json: str | None = None
    try:
        rule_eval = RuleEngine().evaluate(db=db, target=target)
        features = extract_features(rule_eval)
        features_json = json.dumps(features)
    except Exception:
        features_json = None

    tags_str = json.dumps(payload.tags) if payload.tags else None

    review = HumanReview(
        case_id=payload.case_id,
        target=target,
        verdict=payload.verdict,
        reason=payload.reason.strip(),
        analyst=payload.analyst.strip(),
        tags=tags_str,
        features_json=features_json,
        label=label,
    )
    db.add(review)
    db.flush()

    if case is not None:
        # Append an audited case decision event
        event_note = (
            f"Human review verdict: {payload.verdict.upper()}. Reason: {payload.reason.strip()}"
        )
        db.add(
            CaseEvent(
                case_id=case.id,
                event_type="decision",
                note=event_note,
                actor=payload.analyst.strip(),
            )
        )
        # Advance workflow status
        from datetime import UTC, datetime

        case.updated_at = datetime.now(UTC)
        if payload.verdict in (ReviewVerdict.MALICIOUS, ReviewVerdict.BENIGN):
            case.status = CaseStatus.CLOSED
        elif payload.verdict == ReviewVerdict.SUSPICIOUS:
            case.status = CaseStatus.IN_REVIEW

    db.commit()
    db.refresh(review)
    return _serialize_review(review)


@router.get(
    "/review/history",
    response_model=list[ReviewResponse],
    summary="List audited review history",
)
def list_reviews(
    db: Annotated[Session, Depends(get_db)],
    verdict: str | None = None,
    case_id: int | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[ReviewResponse]:
    """Retrieve full audit history of human analyst review verdicts."""
    stmt = select(HumanReview).order_by(HumanReview.id.desc()).limit(limit)
    if verdict:
        stmt = stmt.where(HumanReview.verdict == verdict)
    if case_id is not None:
        stmt = stmt.where(HumanReview.case_id == case_id)

    reviews = list(db.scalars(stmt).all())
    return [_serialize_review(r) for r in reviews]


@router.get(
    "/review/{review_id}",
    response_model=ReviewResponse,
    summary="Read a review verdict by ID",
)
def read_review(review_id: int, db: Annotated[Session, Depends(get_db)]) -> ReviewResponse:
    """Retrieve one specific human review verdict."""
    review = db.get(HumanReview, review_id)
    if review is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Review not found.")
    return _serialize_review(review)


@router.get(
    "/feedback/labels",
    response_model=FeedbackLabelsResponse,
    summary="Retrieve feedback labels for ML retraining",
)
def get_feedback_labels(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> FeedbackLabelsResponse:
    """Retrieve structured labels and feature vectors for model retraining."""
    stmt = select(HumanReview).order_by(HumanReview.id.desc()).limit(limit)
    reviews = list(db.scalars(stmt).all())

    items: list[FeedbackItem] = []
    usable_count = 0
    for r in reviews:
        feats = json.loads(r.features_json) if r.features_json else None
        vector = None
        if feats is not None:
            usable_count += 1
            if isinstance(feats, dict):
                vector = vectorize(feats)
            elif isinstance(feats, list):
                vector = feats
        items.append(
            FeedbackItem(
                review_id=r.id,
                case_id=r.case_id,
                target=r.target,
                verdict=r.verdict,
                label=r.label,
                reason=r.reason,
                analyst=r.analyst,
                features=feats,
                vector=vector,
                created_at=r.created_at,
            )
        )

    return FeedbackLabelsResponse(
        count=len(items),
        usable_training_count=usable_count,
        items=items,
    )
