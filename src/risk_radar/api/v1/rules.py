"""Rule evaluation endpoint (Stage 7)."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from risk_radar.db.session import get_db
from risk_radar.gate.contracts import AnalyzerEvidence
from risk_radar.rules.engine import RuleEngine, RuleEvaluation

router = APIRouter(tags=["rules"])


class RuleEvaluateRequest(BaseModel):
    """Candidate to evaluate. Gate eligibility is never accepted from clients."""

    target: str = Field(min_length=1, max_length=2048)
    kind: Literal["auto", "domain", "handle", "name"] = "auto"
    analysis: AnalyzerEvidence | None = None
    candidate_ref: str | None = Field(default=None, max_length=255)


@router.post("/rules/evaluate", response_model=RuleEvaluation, summary="Evaluate rules")
def evaluate_rules(
    payload: RuleEvaluateRequest,
    db: Annotated[Session, Depends(get_db)],
) -> RuleEvaluation:
    """Run the exclusion gate server-side, then deterministic rules if eligible."""
    return RuleEngine().evaluate(
        db=db,
        target=payload.target,
        kind=payload.kind,
        analysis=payload.analysis,
        candidate_ref=payload.candidate_ref,
    )
