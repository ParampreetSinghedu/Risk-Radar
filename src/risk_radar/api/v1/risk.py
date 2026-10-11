"""Risk × Impact scoring endpoint (Stage 11).

Runs the exclusion gate server-side, then produces a documented, deterministic
prioritization score with detection-risk and business-impact components. Stage 6
remains authoritative; verified official and unverified candidates never receive
an alert-eligible score.
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from risk_radar.api.v1.ml import get_ml_service
from risk_radar.db.session import get_db
from risk_radar.risk.service import RiskImpactEngine, RiskImpactRequest, RiskImpactScore

router = APIRouter(tags=["risk"])


@router.post(
    "/risk/score",
    response_model=RiskImpactScore,
    summary="Score a candidate's risk × impact",
)
def score_risk(
    payload: RiskImpactRequest,
    db: Annotated[Session, Depends(get_db)],
) -> RiskImpactScore:
    """Produce a documented Risk × Impact score for one candidate."""
    return RiskImpactEngine().score(db, payload, ml_service=get_ml_service())
