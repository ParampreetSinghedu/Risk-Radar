"""Domain models for brand intelligence (Stage 1)."""

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from risk_radar.db.base import Base


class AssetType(StrEnum):
    """Official brand asset kinds tracked by Stage 1."""

    NAME = "name"
    LOGO = "logo"
    ACCOUNT = "account"
    APPLICATION = "application"
    DOMAIN = "domain"


def _utcnow() -> datetime:
    """Return the current aware UTC timestamp for row defaults."""
    return datetime.now(UTC)


class Brand(Base):
    """Official brand profile identified by its canonical name."""

    __tablename__ = "brands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class BrandAsset(Base):
    """A single official asset belonging to a brand profile."""

    __tablename__ = "brand_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    brand_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("brands.id"), nullable=False, index=True
    )
    asset_type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class SubmissionType(StrEnum):
    """Supported raw-evidence submission kinds (Stage 2)."""

    URL = "url"
    MESSAGE = "message"
    SCREENSHOT = "screenshot"
    SOCIAL_PROFILE = "social_profile"
    APP_LISTING = "app_listing"


class Submission(Base):
    """Raw user-submitted evidence preserved with source, type and hash (Stage 2)."""

    __tablename__ = "submissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    submission_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    brand_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("brands.id"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class ExclusionAuditLog(Base):
    """Audit trail of Stage 6 exclusion-gate decisions (append-only)."""

    __tablename__ = "exclusion_audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    input_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    brand_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    brand_asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    analyzer_input_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    alert_eligible: Mapped[bool] = mapped_column(Boolean, nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class CaseStatus(StrEnum):
    """Workflow states for a Stage 13 case."""

    OPEN = "open"
    IN_REVIEW = "in_review"
    CLOSED = "closed"


class Case(Base):
    """A triaged investigation case grouping evidence for analyst review (Stage 13)."""

    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=CaseStatus.OPEN)
    # Gate outcome captured when the case was created (never trusted from client).
    gate_outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    alert_eligible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # JSON blob holding the stored stage results snapshot (evidence/risk/etc).
    snapshot: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class CaseEvent(Base):
    """Append-only analyst decision / note on a case (Stage 13 human review)."""

    __tablename__ = "case_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("cases.id"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    actor: Mapped[str] = mapped_column(String(64), nullable=False, default="analyst")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class ReviewVerdict(StrEnum):
    """Supported analyst review verdicts (Stage 14)."""

    MALICIOUS = "malicious"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"


class HumanReview(Base):
    """Audited human analyst review verdict and feedback loop (Stage 14)."""

    __tablename__ = "human_reviews"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("cases.id"), nullable=True, index=True
    )
    target: Mapped[str] = mapped_column(Text, nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    analyst: Mapped[str] = mapped_column(String(64), nullable=False, default="analyst")
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)
    features_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    label: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
