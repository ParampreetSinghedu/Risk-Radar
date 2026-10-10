"""Official-asset exclusion gate endpoints (Stage 6)."""

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from risk_radar.db.models import ExclusionAuditLog
from risk_radar.db.session import get_db
from risk_radar.gate.contracts import AnalyzerEvidence
from risk_radar.gate.service import ExclusionGate, GateDecision

router = APIRouter(tags=["gate"])


class GateEvaluateRequest(BaseModel):
    """One target to evaluate against official brand assets."""

    target: str = Field(min_length=1, max_length=2048)
    kind: Literal["auto", "domain", "handle", "name"] = "auto"
    analysis: AnalyzerEvidence | None = None


class AuditLogResponse(BaseModel):
    """One recorded exclusion-gate decision."""

    model_config = {"from_attributes": True}

    id: int
    input_reference: str
    decision: str
    reason: str
    brand_id: int | None
    brand_asset_id: int | None
    analyzer_input_id: str | None
    alert_eligible: bool
    decided_at: datetime


@router.post("/gate/evaluate", response_model=GateDecision, summary="Evaluate a target")
def evaluate(
    payload: GateEvaluateRequest,
    db: Annotated[Session, Depends(get_db)],
) -> GateDecision:
    """Return the exclusion-gate decision and record it in the audit log."""
    gate = ExclusionGate()
    return gate.evaluate(
        db=db,
        target=payload.target,
        kind=payload.kind,
        analysis=payload.analysis,
    )


@router.get(
    "/gate/audit",
    response_model=list[AuditLogResponse],
    summary="List exclusion audit entries",
)
def list_audit(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Field(ge=1, le=200)] = 50,
) -> list[ExclusionAuditLog]:
    """Return the most recent recorded gate decisions."""
    stmt = select(ExclusionAuditLog).order_by(ExclusionAuditLog.id.desc()).limit(limit)
    return list(db.scalars(stmt).all())
