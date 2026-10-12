"""Case management endpoints (Stage 13).

Cases group a candidate with its gate decision and a snapshot of stage results
for analyst triage. The exclusion gate is always re-evaluated server-side when a
case is created: a verified official asset is never stored as alert-eligible and
an unverified identity is marked for verification. The LLM or any downstream
stage can never override that.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import case as sql_case
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from risk_radar.db.models import Case, CaseEvent, CaseStatus
from risk_radar.db.session import get_db
from risk_radar.gate.service import ExclusionGate

router = APIRouter(tags=["cases"])

_EVENT_TYPES = {"note", "decision", "status_change"}


class CaseCreate(BaseModel):
    """Payload to open a case for one candidate."""

    title: str = Field(min_length=1, max_length=255)
    target: str = Field(min_length=1, max_length=2048)
    kind: Literal["auto", "domain", "handle", "name", "application"] = "auto"
    # Optional stage-results snapshot (already-computed evidence/risk/etc).
    snapshot: dict | None = None
    note: str | None = Field(default=None, max_length=4000)


class CaseStatusUpdate(BaseModel):
    """Move a case through open -> in_review -> closed."""

    status: Literal["open", "in_review", "closed"]
    note: str | None = Field(default=None, max_length=4000)
    actor: str = Field(default="analyst", max_length=64)


class CaseEventCreate(BaseModel):
    """Record an analyst decision or note on a case."""

    event_type: Literal["note", "decision"] = "note"
    note: str = Field(min_length=1, max_length=4000)
    actor: str = Field(default="analyst", max_length=64)


class CaseEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    event_type: str
    note: str
    actor: str
    created_at: datetime


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    target: str
    status: str
    gate_outcome: str | None
    alert_eligible: bool
    created_at: datetime
    updated_at: datetime
    events: list[CaseEventResponse] = Field(default_factory=list)


class CaseReport(BaseModel):
    """Readable case report assembled from real stored data only."""

    case_id: int
    title: str
    target: str
    status: str
    gate_outcome: str | None
    alert_eligible: bool
    created_at: datetime
    updated_at: datetime
    analyst_events: list[CaseEventResponse] = Field(default_factory=list)
    snapshot_available: bool
    snapshot: dict | None = None
    report_sections: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


def _case_with_events(db: Session, case: Case) -> CaseResponse:
    events = list(
        db.scalars(
            select(CaseEvent).where(CaseEvent.case_id == case.id).order_by(CaseEvent.id)
        ).all()
    )
    response = CaseResponse.model_validate(case)
    response.events = [CaseEventResponse.model_validate(e) for e in events]
    return response


def _touch(case: Case) -> None:
    from datetime import UTC, datetime

    case.updated_at = datetime.now(UTC)


@router.post(
    "/cases",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Open a case",
)
def create_case(payload: CaseCreate, db: Annotated[Session, Depends(get_db)]) -> CaseResponse:
    """Open a case after a server-side gate decision (never client-supplied)."""
    try:
        decision = ExclusionGate().evaluate(db=db, target=payload.target, kind=payload.kind)
    except Exception as exc:  # noqa: BLE001 - fail closed on gate failure
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"gate decision unavailable ({exc.__class__.__name__}); case not created",
        ) from exc

    case = Case(
        title=payload.title,
        target=payload.target,
        status=CaseStatus.OPEN,
        gate_outcome=decision.outcome,
        alert_eligible=decision.alert_eligible,
        snapshot=json.dumps(payload.snapshot) if payload.snapshot else None,
    )
    db.add(case)
    db.flush()
    db.add(
        CaseEvent(
            case_id=case.id,
            event_type="status_change",
            note=f"case opened; gate outcome: {decision.outcome}",
            actor="system",
        )
    )
    if payload.note:
        db.add(CaseEvent(case_id=case.id, event_type="note", note=payload.note, actor="analyst"))
    db.commit()
    db.refresh(case)
    return _case_with_events(db, case)


@router.get("/cases", response_model=list[CaseResponse], summary="List cases")
def list_cases(
    db: Annotated[Session, Depends(get_db)],
    case_status: Literal["open", "in_review", "closed"] | None = None,
    limit: Annotated[int, Field(ge=1, le=200)] = 50,
) -> list[CaseResponse]:
    """Return recent cases (optionally filtered by workflow status)."""
    stmt = select(Case).order_by(Case.id.desc()).limit(limit)
    if case_status is not None:
        stmt = stmt.where(Case.status == case_status)
    cases = list(db.scalars(stmt).all())
    return [_case_with_events(db, case) for case in cases]


@router.get("/cases/{case_id}", response_model=CaseResponse, summary="Read a case")
def read_case(case_id: int, db: Annotated[Session, Depends(get_db)]) -> CaseResponse:
    """Return one case with its analyst events."""
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    return _case_with_events(db, case)


@router.patch("/cases/{case_id}/status", response_model=CaseResponse, summary="Update case status")
def update_case_status(
    case_id: int, payload: CaseStatusUpdate, db: Annotated[Session, Depends(get_db)]
) -> CaseResponse:
    """Transition a case status and record the analyst decision."""
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    previous = case.status
    case.status = payload.status
    _touch(case)
    db.add(
        CaseEvent(
            case_id=case.id,
            event_type="status_change",
            note=payload.note or f"status changed from {previous} to {payload.status}",
            actor=payload.actor,
        )
    )
    db.commit()
    db.refresh(case)
    return _case_with_events(db, case)


@router.post("/cases/{case_id}/events", response_model=CaseResponse, summary="Add a case event")
def add_case_event(
    case_id: int, payload: CaseEventCreate, db: Annotated[Session, Depends(get_db)]
) -> CaseResponse:
    """Record an analyst note or decision (Stage 13 human review)."""
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if payload.event_type not in _EVENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid event type"
        )
    db.add(
        CaseEvent(
            case_id=case.id,
            event_type=payload.event_type,
            note=payload.note,
            actor=payload.actor,
        )
    )
    _touch(case)
    db.commit()
    db.refresh(case)
    return _case_with_events(db, case)


@router.get("/cases/{case_id}/report", response_model=CaseReport, summary="Generate case report")
def case_report(case_id: int, db: Annotated[Session, Depends(get_db)]) -> CaseReport:
    """Generate a readable report from real stored case data only."""
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    events = list(
        db.scalars(
            select(CaseEvent).where(CaseEvent.case_id == case.id).order_by(CaseEvent.id)
        ).all()
    )
    snapshot = json.loads(case.snapshot) if case.snapshot else None

    sections = [
        f"Case #{case.id}: {case.title}",
        f"Target: {case.target}",
        f"Workflow status: {case.status}",
        f"Stage 6 gate outcome: {case.gate_outcome or 'unknown'}",
    ]
    limitations: list[str] = []
    if case.alert_eligible:
        sections.append("Alert eligibility: eligible (gate-authorized)")
    else:
        sections.append(
            "Alert eligibility: NOT eligible"
            + (" (verified official asset)" if case.gate_outcome == "verified_official" else "")
        )
    if snapshot:
        sections.append(f"Stage-results snapshot captured ({len(snapshot)} section(s)).")
    else:
        limitations.append("no stage-results snapshot was attached to this case")
    if not events:
        limitations.append("no analyst decisions have been recorded yet")

    return CaseReport(
        case_id=case.id,
        title=case.title,
        target=case.target,
        status=case.status,
        gate_outcome=case.gate_outcome,
        alert_eligible=case.alert_eligible,
        created_at=case.created_at,
        updated_at=case.updated_at,
        analyst_events=[CaseEventResponse.model_validate(e) for e in events],
        snapshot_available=snapshot is not None,
        snapshot=snapshot,
        report_sections=sections,
        limitations=limitations,
    )


class DashboardSummary(BaseModel):
    """Aggregate counts for the dashboard, computed from real stored data."""

    total_cases: int = 0
    open_cases: int = 0
    in_review_cases: int = 0
    closed_cases: int = 0
    alert_eligible_cases: int = 0
    verified_official_cases: int = 0
    recent_cases: list[CaseResponse] = Field(default_factory=list)
    data_available: bool = True


@router.get("/dashboard", response_model=DashboardSummary, summary="Dashboard summary")
def dashboard_summary(db: Annotated[Session, Depends(get_db)]) -> DashboardSummary:
    """Return real case counts and recent cases for the dashboard."""
    totals = db.execute(
        select(
            func.count(Case.id),
            func.coalesce(func.sum(sql_case((Case.status == "open", 1), else_=0)), 0),
            func.coalesce(func.sum(sql_case((Case.status == "in_review", 1), else_=0)), 0),
            func.coalesce(func.sum(sql_case((Case.status == "closed", 1), else_=0)), 0),
            func.coalesce(func.sum(sql_case((Case.alert_eligible.is_(True), 1), else_=0)), 0),
            func.coalesce(
                func.sum(sql_case((Case.gate_outcome == "verified_official", 1), else_=0)), 0
            ),
        )
    ).one()
    recent = list(db.scalars(select(Case).order_by(Case.id.desc()).limit(10)).all())
    if not totals[0]:
        # Explicit empty state: no fabricated numbers.
        return DashboardSummary(data_available=True, recent_cases=[])
    return DashboardSummary(
        total_cases=totals[0],
        open_cases=totals[1],
        in_review_cases=totals[2],
        closed_cases=totals[3],
        alert_eligible_cases=totals[4],
        verified_official_cases=totals[5],
        recent_cases=[_case_with_events(db, c) for c in recent],
        data_available=True,
    )
