"""Persisted monitoring targets, scheduled checks, change alerts and review."""

import json
import re
from datetime import UTC, datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from risk_radar.core.config import get_settings
from risk_radar.db.models import (
    Brand,
    MonitoringAlert,
    MonitoringCheck,
    MonitoringTarget,
)
from risk_radar.db.session import get_db
from risk_radar.evidence.application import ApplicationListingAnalyzer
from risk_radar.monitoring.service import MonitoringService

router = APIRouter(tags=["monitoring"])
_HANDLE = re.compile(r"^@[A-Za-z0-9_.]{1,50}$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?$"
)


class MonitoringTargetCreate(BaseModel):
    target_type: Literal["domain", "social_profile", "application"]
    target: str = Field(min_length=1, max_length=2048)
    brand_id: int | None = None
    interval_seconds: int = Field(default=3600, ge=60, le=2_592_000)

    @model_validator(mode="after")
    def normalize_target(self):
        value = self.target.strip()
        if self.target_type == "domain":
            parts = urlsplit(value if "://" in value else "//" + value)
            if parts.scheme not in {"", "http", "https"} or not parts.hostname:
                raise ValueError("domain target must be a hostname or http(s) URL")
            if parts.username or parts.password or parts.port:
                raise ValueError("domain target cannot include credentials or a port")
            if not _DOMAIN.fullmatch(parts.hostname):
                raise ValueError("domain target must be a valid public-style DNS name")
            self.target = parts.hostname.lower().rstrip(".")
        elif self.target_type == "social_profile":
            if not _HANDLE.fullmatch(value):
                raise ValueError("social profile target must be a plain @handle")
            self.target = value.lower()
        else:
            if ApplicationListingAnalyzer._parse(value) is None:
                raise ValueError(
                    "application target must be a supported store URL, package ID, "
                    "or numeric store ID"
                )
            self.target = value
        return self


class MonitoringTargetPatch(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=60, le=2_592_000)

    @model_validator(mode="after")
    def require_a_change(self):
        if self.enabled is None and self.interval_seconds is None:
            raise ValueError("provide enabled or interval_seconds")
        return self


class MonitoringTargetResponse(BaseModel):
    id: int
    brand_id: int | None
    target_type: str
    target: str
    enabled: bool
    removed: bool
    interval_seconds: int
    created_at: datetime
    updated_at: datetime
    next_check_at: datetime | None
    last_check_at: datetime | None
    last_success_at: datetime | None
    last_status: str
    last_error: str | None
    active_monitoring: bool

    @classmethod
    def from_model(cls, row: MonitoringTarget):
        return cls(
            id=row.id,
            brand_id=row.brand_id,
            target_type=row.target_type,
            target=row.target,
            enabled=row.enabled,
            removed=row.removed,
            interval_seconds=row.interval_seconds,
            created_at=row.created_at,
            updated_at=row.updated_at,
            next_check_at=row.next_check_at,
            last_check_at=row.last_check_at,
            last_success_at=row.last_success_at,
            last_status=row.last_status,
            last_error=row.last_error,
            active_monitoring=bool(row.enabled and not row.removed and row.last_success_at),
        )


class MonitoringCheckResponse(BaseModel):
    id: int
    target_id: int
    status: str
    started_at: datetime
    finished_at: datetime
    providers: dict
    result: dict
    error: str | None

    @classmethod
    def from_model(cls, row: MonitoringCheck):
        return cls(
            id=row.id,
            target_id=row.target_id,
            status=row.status,
            started_at=row.started_at,
            finished_at=row.finished_at,
            providers=json.loads(row.providers_json),
            result=json.loads(row.result_json),
            error=row.error,
        )


class MonitoringAlertResponse(BaseModel):
    id: int
    target_id: int
    target: str
    target_type: str
    check_id: int
    observation_id: int
    change_type: str
    summary: str
    evidence: dict
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    created_at: datetime


class AlertAcknowledge(BaseModel):
    acknowledged_by: str = Field(default="analyst", min_length=1, max_length=64)


class MonitoringRuntimeStatus(BaseModel):
    scheduler_enabled: bool
    scheduler_poll_seconds: float
    scheduler_batch_size: int
    providers: dict[str, str]


def _target_or_404(db: Session, target_id: int) -> MonitoringTarget:
    row = db.get(MonitoringTarget, target_id)
    if row is None or row.removed:
        raise HTTPException(status_code=404, detail="Monitoring target not found")
    return row


@router.get("/monitoring/status", response_model=MonitoringRuntimeStatus)
def monitoring_status():
    settings = get_settings()
    return MonitoringRuntimeStatus(
        scheduler_enabled=settings.monitoring_scheduler_enabled,
        scheduler_poll_seconds=settings.monitoring_scheduler_poll_seconds,
        scheduler_batch_size=settings.monitoring_scheduler_batch_size,
        providers={
            "social": "unavailable: no authorized platform provider configured",
            "apple_app_store": "configured: official lookup endpoint; network not probed",
            "google_play": "unavailable: no authorized metadata source configured",
            "dns_rdap": "enabled"
            if settings.evidence_enable_live_resolvers
            else "disabled by configuration",
            "redirects": "enabled"
            if settings.evidence_enable_redirects
            else "disabled by configuration",
        },
    )


@router.post("/monitoring/targets", response_model=MonitoringTargetResponse, status_code=201)
def create_target(payload: MonitoringTargetCreate, db: Annotated[Session, Depends(get_db)]):
    if payload.brand_id is not None and db.get(Brand, payload.brand_id) is None:
        raise HTTPException(status_code=404, detail="Brand not found")
    now = datetime.now(UTC)
    existing = db.scalar(
        select(MonitoringTarget).where(
            MonitoringTarget.target_type == payload.target_type,
            MonitoringTarget.target == payload.target,
        )
    )
    if existing is not None:
        if not existing.removed:
            raise HTTPException(status_code=409, detail="Monitoring target already exists")
        existing.removed = False
        existing.enabled = True
        existing.brand_id = payload.brand_id
        existing.interval_seconds = payload.interval_seconds
        existing.next_check_at = now
        existing.last_status = (
            "never_checked" if existing.last_success_at is None else existing.last_status
        )
        existing.last_error = None
        existing.updated_at = now
        db.commit()
        db.refresh(existing)
        return MonitoringTargetResponse.from_model(existing)
    row = MonitoringTarget(
        target_type=payload.target_type,
        target=payload.target,
        brand_id=payload.brand_id,
        interval_seconds=payload.interval_seconds,
        enabled=True,
        removed=False,
        next_check_at=now,
        last_status="never_checked",
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Monitoring target already exists") from exc
    db.refresh(row)
    return MonitoringTargetResponse.from_model(row)


@router.get("/monitoring/targets", response_model=list[MonitoringTargetResponse])
def list_targets(db: Annotated[Session, Depends(get_db)]):
    rows = db.scalars(
        select(MonitoringTarget)
        .where(MonitoringTarget.removed.is_(False))
        .order_by(MonitoringTarget.id)
    )
    return [MonitoringTargetResponse.from_model(row) for row in rows]


@router.get("/monitoring/targets/{target_id}", response_model=MonitoringTargetResponse)
def read_target(target_id: int, db: Annotated[Session, Depends(get_db)]):
    return MonitoringTargetResponse.from_model(_target_or_404(db, target_id))


@router.patch("/monitoring/targets/{target_id}", response_model=MonitoringTargetResponse)
def update_target(
    target_id: int,
    payload: MonitoringTargetPatch,
    db: Annotated[Session, Depends(get_db)],
):
    row = _target_or_404(db, target_id)
    now = datetime.now(UTC)
    if payload.enabled is not None:
        row.enabled = payload.enabled
        row.next_check_at = now if payload.enabled else None
    if payload.interval_seconds is not None:
        row.interval_seconds = payload.interval_seconds
        if row.enabled:
            row.next_check_at = now
    row.updated_at = now
    db.commit()
    db.refresh(row)
    return MonitoringTargetResponse.from_model(row)


@router.delete("/monitoring/targets/{target_id}", response_model=MonitoringTargetResponse)
def remove_target(target_id: int, db: Annotated[Session, Depends(get_db)]):
    row = _target_or_404(db, target_id)
    row.enabled = False
    row.removed = True
    row.next_check_at = None
    row.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(row)
    return MonitoringTargetResponse.from_model(row)


@router.post("/monitoring/targets/{target_id}/check", response_model=MonitoringCheckResponse)
def run_target_check(target_id: int, db: Annotated[Session, Depends(get_db)]):
    _target_or_404(db, target_id)
    check = MonitoringService().run_check(db, target_id, force=True)
    if check is None:
        raise HTTPException(
            status_code=409, detail="Target is paused or a check is already running"
        )
    return MonitoringCheckResponse.from_model(check)


@router.get("/monitoring/targets/{target_id}/checks", response_model=list[MonitoringCheckResponse])
def list_checks(
    target_id: int,
    db: Annotated[Session, Depends(get_db)],
    limit: int = 50,
):
    _target_or_404(db, target_id)
    bounded_limit = min(max(limit, 1), 200)
    rows = db.scalars(
        select(MonitoringCheck)
        .where(MonitoringCheck.target_id == target_id)
        .order_by(MonitoringCheck.id.desc())
        .limit(bounded_limit)
    )
    return [MonitoringCheckResponse.from_model(row) for row in rows]


@router.get(
    "/monitoring/targets/{target_id}/checks/{check_id}",
    response_model=MonitoringCheckResponse,
)
def read_check(
    target_id: int,
    check_id: int,
    db: Annotated[Session, Depends(get_db)],
):
    _target_or_404(db, target_id)
    row = db.get(MonitoringCheck, check_id)
    if row is None or row.target_id != target_id:
        raise HTTPException(status_code=404, detail="Monitoring check not found")
    return MonitoringCheckResponse.from_model(row)


@router.get("/monitoring/alerts", response_model=list[MonitoringAlertResponse])
def list_alerts(
    db: Annotated[Session, Depends(get_db)],
    acknowledged: bool | None = None,
    limit: int = 100,
):
    stmt = (
        select(MonitoringAlert, MonitoringTarget)
        .join(MonitoringTarget, MonitoringTarget.id == MonitoringAlert.target_id)
        .order_by(MonitoringAlert.id.desc())
    )
    if acknowledged is True:
        stmt = stmt.where(MonitoringAlert.acknowledged_at.is_not(None))
    elif acknowledged is False:
        stmt = stmt.where(MonitoringAlert.acknowledged_at.is_(None))
    rows = db.execute(stmt.limit(min(max(limit, 1), 200))).all()
    return [
        MonitoringAlertResponse(
            id=alert.id,
            target_id=alert.target_id,
            target=target.target,
            target_type=target.target_type,
            check_id=alert.check_id,
            observation_id=alert.observation_id,
            change_type=alert.change_type,
            summary=alert.summary,
            evidence=json.loads(alert.evidence_json),
            acknowledged_at=alert.acknowledged_at,
            acknowledged_by=alert.acknowledged_by,
            created_at=alert.created_at,
        )
        for alert, target in rows
    ]


@router.post("/monitoring/alerts/{alert_id}/acknowledge", response_model=MonitoringAlertResponse)
def acknowledge_alert(
    alert_id: int,
    payload: AlertAcknowledge,
    db: Annotated[Session, Depends(get_db)],
):
    alert = db.get(MonitoringAlert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Monitoring alert not found")
    if alert.acknowledged_at is None:
        alert.acknowledged_at = datetime.now(UTC)
        alert.acknowledged_by = payload.acknowledged_by.strip() or "analyst"
        db.commit()
        db.refresh(alert)
    target = db.get(MonitoringTarget, alert.target_id)
    return MonitoringAlertResponse(
        id=alert.id,
        target_id=alert.target_id,
        target=target.target,
        target_type=target.target_type,
        check_id=alert.check_id,
        observation_id=alert.observation_id,
        change_type=alert.change_type,
        summary=alert.summary,
        evidence=json.loads(alert.evidence_json),
        acknowledged_at=alert.acknowledged_at,
        acknowledged_by=alert.acknowledged_by,
        created_at=alert.created_at,
    )
