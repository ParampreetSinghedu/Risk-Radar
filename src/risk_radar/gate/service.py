"""Official-asset exclusion gate: three outcomes, all audited (Stage 6)."""

import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from risk_radar.db.models import Brand, BrandAsset, ExclusionAuditLog
from risk_radar.gate.contracts import AnalyzerEvidence, ClaimedIdentity, claimed_identities

Outcome = Literal["verified_official", "unverified", "not_matched"]
Kind = Literal["auto", "domain", "handle", "name"]

# Where each outcome goes next. Only "not_matched" reaches detection.
NEXT_STAGE: dict[str, str | None] = {
    "verified_official": None,
    "unverified": "verification",
    "not_matched": "detection",
}

_BARE_DOMAIN = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_ASSET_TYPES: dict[str, tuple[str, ...]] = {
    "domain": ("domain",),
    "handle": ("account",),
    "name": ("name",),
}


class GateDecision(BaseModel):
    """Result of one exclusion-gate evaluation."""

    outcome: Outcome
    next_stage: str | None
    alert_eligible: bool
    reason: str
    matched_brand_id: int | None = None
    matched_asset_id: int | None = None
    matched_value: str | None = None
    input_reference: str
    audit_id: int | None = None
    limitations: list[str] = Field(default_factory=list)


def extract_identity(target: str, kind: Kind = "auto") -> tuple[Kind, str]:
    """Derive (kind, needle) from a raw target; never raises on odd input."""
    value = target.strip()
    if kind != "auto":
        return kind, _needle(kind, value)
    if "://" in value:
        try:
            host = urlsplit(value).hostname
        except ValueError:
            host = None
        if host:
            return "domain", _needle("domain", host)
    if value.startswith("@"):
        return "handle", _needle("handle", value)
    if _BARE_DOMAIN.fullmatch(value):
        return "domain", _needle("domain", value)
    return "name", _needle("name", value)


def _needle(kind: str, value: str) -> str:
    """Canonicalize a value for case-insensitive exact matching."""
    cleaned = value.strip().lower().rstrip(".")
    if kind == "handle":
        return cleaned if cleaned.startswith("@") else f"@{cleaned}"
    return cleaned


def _handle_variants(needle: str) -> list[str]:
    return [needle, needle.lstrip("@")]


def find_matches(db: Session, kind: str, needle: str) -> list[tuple[BrandAsset, Brand]]:
    """Return Stage 1 assets matching the claimed identity."""
    if kind == "handle":
        condition = func.lower(BrandAsset.value).in_(_handle_variants(needle))
    else:
        condition = func.lower(BrandAsset.value) == needle
    stmt = (
        select(BrandAsset, Brand)
        .join(Brand, Brand.id == BrandAsset.brand_id)
        .where(condition)
        .where(BrandAsset.asset_type.in_(_ASSET_TYPES[kind]))
        .order_by(BrandAsset.id)
    )
    rows = list(db.execute(stmt).all())
    if kind == "name":
        name_stmt = (
            select(BrandAsset, Brand)
            .join(Brand, Brand.id == BrandAsset.brand_id)
            .where(func.lower(Brand.name) == needle)
            .order_by(BrandAsset.id)
        )
        rows.extend(db.execute(name_stmt).all())
    return rows


class ExclusionGate:
    """Decide verified official vs unverified vs not matched; audit everything."""

    def evaluate(
        self,
        db: Session,
        target: str,
        kind: Kind = "auto",
        analysis: AnalyzerEvidence | None = None,
    ) -> GateDecision:
        """Evaluate one target against Stage 1 official assets and log the decision."""
        limitations: list[str] = []
        identities: list[ClaimedIdentity] = []

        base_kind, base_value = extract_identity(target, kind)
        identities.append(
            ClaimedIdentity(
                kind=base_kind, value=base_value, confidence=None, evidence_input_id="target"
            )
        )
        if analysis is not None:
            from_analysis, analysis_limits = claimed_identities(analysis)
            identities.extend(from_analysis)
            limitations.extend(analysis_limits)

        best: Outcome = "not_matched"
        matched_asset: BrandAsset | None = None
        matched_brand: Brand | None = None
        matched_on: str | None = None
        seen: set[tuple[str, str]] = set()

        for identity in identities:
            needle = _needle(identity.kind, identity.value)
            if (identity.kind, needle) in seen:
                continue
            seen.add((identity.kind, needle))
            for asset, brand in find_matches(db, identity.kind, needle):
                if asset.verified:
                    best = "verified_official"
                    matched_asset, matched_brand, matched_on = asset, brand, identity.value
                    break
                if best != "verified_official":
                    best = "unverified"
                    if matched_asset is None:
                        matched_asset, matched_brand, matched_on = asset, brand, identity.value
            if best == "verified_official":
                break

        reason = {
            "verified_official": f"matched verified official asset {matched_on!r}",
            "unverified": f"matched unverified official asset {matched_on!r}",
            "not_matched": "no official asset matched the claimed identity",
        }[best]
        alert_eligible = best == "not_matched"
        decision = GateDecision(
            outcome=best,
            next_stage=NEXT_STAGE[best],
            alert_eligible=alert_eligible,
            reason=reason,
            matched_brand_id=matched_brand.id if matched_brand else None,
            matched_asset_id=matched_asset.id if matched_asset else None,
            matched_value=matched_on,
            input_reference=target[:255],
            limitations=limitations,
        )

        audit = ExclusionAuditLog(
            input_reference=target[:255],
            decision=best,
            reason=reason,
            brand_id=decision.matched_brand_id,
            brand_asset_id=decision.matched_asset_id,
            analyzer_input_id=(
                analysis.source_reference.input_id if analysis is not None else None
            ),
            alert_eligible=alert_eligible,
        )
        db.add(audit)
        db.commit()
        db.refresh(audit)
        decision.audit_id = audit.id
        return decision
