"""ML scoring endpoints (Stage 8)."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from risk_radar.db.session import get_db
from risk_radar.gate.contracts import AnalyzerEvidence
from risk_radar.ml.service import DatasetRow, MLScoreResult, MLService, TrainingResult
from risk_radar.rules.engine import RuleEngine

router = APIRouter(tags=["ml"])

_service = MLService()


def get_ml_service() -> MLService:
    """Return the process-wide ML service (in-memory model, no serving stack)."""
    return _service


class MLScoreRequest(BaseModel):
    """Candidate to score; gate eligibility is decided server-side only."""

    target: str = Field(min_length=1, max_length=2048)
    kind: Literal["auto", "domain", "handle", "name"] = "auto"
    analysis: AnalyzerEvidence | None = None
    candidate_ref: str | None = Field(default=None, max_length=255)


class MLTrainRequest(BaseModel):
    """Labeled dataset for training the ranking model."""

    dataset: list[DatasetRow] = Field(min_length=1)


@router.post("/ml/score", response_model=MLScoreResult, summary="Score a candidate")
def score_candidate(
    payload: MLScoreRequest,
    db: Annotated[Session, Depends(get_db)],
) -> MLScoreResult:
    """Run the rule engine, then score only if the gate allows evaluation."""
    evaluation = RuleEngine().evaluate(
        db=db,
        target=payload.target,
        kind=payload.kind,
        analysis=payload.analysis,
        candidate_ref=payload.candidate_ref,
    )
    ref = payload.candidate_ref or payload.target
    return get_ml_service().score(candidate_ref=ref, rule_evaluation=evaluation)


@router.post("/ml/train", response_model=TrainingResult, summary="Train the model")
def train_model(payload: MLTrainRequest) -> TrainingResult:
    """Train on labeled feature rows and report held-out baseline vs model."""
    return get_ml_service().train(payload.dataset)
