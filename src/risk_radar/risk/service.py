"""Risk × Impact engine (Stage 11).

Combines detection risk with business impact into one documented,
deterministic prioritization score. Stage 6 stays authoritative: the gate is
re-evaluated server-side on every request and only ``not_matched`` candidates
receive an actionable score.

Scoring model (deterministic, weights are module constants):

    detection_risk = 0.60 * rule_risk   + 0.40 * ml_risk
    business_impact (0..1 or None when no impact data exists)
    overall_score  = detection_risk * business_impact_multiplier

``rule_risk`` is a severity-weighted mean of matched rule findings.
``ml_risk`` is the Stage 8 ranking score when a trained model produced one; it
is a ranking value, NOT a calibrated probability of maliciousness, and it is
omitted (weight redistributed) when unavailable so a missing model never
fabricates risk.

``business_impact`` is derived only from genuinely available Stage 1 brand and
stored-report data. When no impact signal exists it is ``None`` and the
multiplier is neutral (1.0); missing impact data never invents reach, target
importance or impact labels. Correlation (Stage 10) never sets maliciousness:
campaign context may adjust impact but never detection risk, and it is only
applied when explicitly supplied and evidenced.

Every component exposes its formula, weights, contributing signals and
evidence references so a reviewer can trace how the score was produced.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from risk_radar.db.models import Brand, BrandAsset, Submission
from risk_radar.gate.contracts import AnalyzerEvidence
from risk_radar.gate.service import ExclusionGate, GateDecision
from risk_radar.ml.service import MLService
from risk_radar.rules.engine import RuleEngine, RuleEvaluation

# --- documented weights (module constants, not secrets) -------------------

RULE_WEIGHT = 0.60
ML_WEIGHT = 0.40

_SEVERITY_RISK = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.25,
    "informational": 0.1,
}

ImpactStatus = Literal["available", "unavailable"]
ScoreStatus = Literal[
    "scored",
    "excluded_verified_official",
    "routed_to_verification",
    "failed_closed",
]


class ContributingSignal(BaseModel):
    """One traceable input that moved a score component."""

    name: str
    component: Literal["detection", "impact"]
    contribution: float
    reason: str
    evidence_refs: list[str] = Field(default_factory=list)


class DetectionRisk(BaseModel):
    """Detection-risk component with its formula and contributing signals."""

    score: float | None = Field(default=None, ge=0, le=1)
    formula: str
    rule_risk: float | None = Field(default=None, ge=0, le=1)
    ml_risk: float | None = Field(default=None, ge=0, le=1)
    ml_semantics: str | None = None
    weights: dict[str, float] = Field(default_factory=dict)
    signals: list[ContributingSignal] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class BusinessImpact(BaseModel):
    """Business-impact component; None when no genuine impact data exists."""

    status: ImpactStatus
    score: float | None = Field(default=None, ge=0, le=1)
    formula: str
    signals: list[ContributingSignal] = Field(default_factory=list)
    missing_data: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class RiskImpactScore(BaseModel):
    """Full Risk × Impact output for one candidate."""

    schema_version: str = "1.0"
    status: ScoreStatus
    candidate_ref: str
    gate_decision: GateDecision | None = None
    detection_risk: DetectionRisk | None = None
    business_impact: BusinessImpact | None = None
    overall_score: float | None = Field(default=None, ge=0, le=1)
    overall_formula: str
    score_semantics: str = (
        "prioritization ranking output; NOT a calibrated probability of maliciousness"
    )
    alert_eligible: bool = False
    input_quality: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    errors: list[dict[str, str]] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RiskImpactRequest(BaseModel):
    """Candidate to score; gate eligibility is decided server-side only."""

    target: str = Field(min_length=1, max_length=2048)
    kind: Literal["auto", "domain", "handle", "name", "application"] = "auto"
    analysis: AnalyzerEvidence | None = None
    candidate_ref: str | None = Field(default=None, max_length=255)
    # Optional Stage 9/10 context. Correlation alone never sets maliciousness.
    campaign_context_size: int | None = Field(default=None, ge=0)
    campaign_evidence_refs: list[str] = Field(default_factory=list)


def _rule_risk(
    evaluation: RuleEvaluation,
) -> tuple[float | None, list[ContributingSignal], list[str]]:
    """Severity-weighted mean of matched rule findings (deterministic)."""
    if not evaluation.findings:
        return (
            0.0,
            [],
            ["no rules matched: detection risk from rules is zero, not 'safe'"],
        )
    signals: list[ContributingSignal] = []
    total = 0.0
    for finding in evaluation.findings:
        weight = _SEVERITY_RISK.get(finding.severity, 0.1)
        # Blend in finding confidence when present, but never above the severity weight.
        confidence = finding.confidence if finding.confidence is not None else 1.0
        contribution = weight * max(0.0, min(1.0, confidence))
        total += contribution
        signals.append(
            ContributingSignal(
                name=finding.rule_id,
                component="detection",
                contribution=round(contribution, 4),
                reason=finding.reason,
                evidence_refs=list(finding.evidence_refs),
            )
        )
    # Mean, so many low findings do not automatically outweigh one critical one.
    risk = min(1.0, total / len(evaluation.findings))
    return round(risk, 4), signals, []


class RiskImpactEngine:
    """Score gate-eligible candidates; never overrides Stage 6."""

    def __init__(self, ml_service: MLService | None = None) -> None:
        self._ml = ml_service

    def score(
        self,
        db: Session,
        request: RiskImpactRequest,
        ml_service: MLService | None = None,
    ) -> RiskImpactScore:
        """Produce a documented Risk × Impact score for one candidate."""
        ref = (request.candidate_ref or request.target)[:255]
        ml = ml_service or self._ml

        # Stage 6 first, server-side, always.
        try:
            decision: GateDecision = ExclusionGate().evaluate(
                db=db,
                target=request.target,
                kind=request.kind,
                analysis=request.analysis,
                record_audit=False,
            )
        except Exception as exc:  # noqa: BLE001 - fail closed on any gate failure
            return RiskImpactScore(
                status="failed_closed",
                candidate_ref=ref,
                overall_formula="n/a (gate unavailable)",
                errors=[{"stage": "exclusion_gate", "message": exc.__class__.__name__}],
                limitations=["gate decision unavailable: scoring failed closed"],
            )

        if decision.outcome == "verified_official":
            return RiskImpactScore(
                status="excluded_verified_official",
                candidate_ref=ref,
                gate_decision=decision,
                overall_formula="n/a (verified official excluded)",
                alert_eligible=False,
                limitations=["verified official asset excluded by Stage 6; no score produced"],
            )
        if decision.outcome == "unverified":
            return RiskImpactScore(
                status="routed_to_verification",
                candidate_ref=ref,
                gate_decision=decision,
                overall_formula="n/a (held for verification)",
                alert_eligible=False,
                limitations=["unverified identity held for verification by Stage 6; no score"],
            )

        # Rules (Stage 7) for detection risk.
        try:
            evaluation = RuleEngine().evaluate(
                db=db,
                target=request.target,
                kind=request.kind,
                analysis=request.analysis,
                candidate_ref=ref,
            )
        except Exception as exc:  # noqa: BLE001 - fail closed on rule-engine errors
            return RiskImpactScore(
                status="failed_closed",
                candidate_ref=ref,
                gate_decision=decision,
                overall_formula="n/a (rule engine unavailable)",
                errors=[{"stage": "rule_engine", "message": exc.__class__.__name__}],
                limitations=["rule evaluation unavailable: scoring failed closed"],
            )

        detection, detection_limitations, input_quality = self._detection_risk(evaluation, ref, ml)
        impact = self._business_impact(db, request, decision)

        limitations = list(detection_limitations)
        if request.analysis is not None:
            input_quality.append(f"analyzer={request.analysis.analyzer_type}")
            input_quality.append(f"analyzer_status={request.analysis.status}")
            if request.analysis.limitations:
                limitations.extend(request.analysis.limitations)
        else:
            input_quality.append("analyzers_run=0")
            limitations.append(
                "no analyzer evidence supplied: detection relies strictly on "
                "candidate string and stored records"
            )

        # Combine with neutral multiplier when impact data is missing.
        multiplier = impact.score if (impact and impact.score is not None) else 1.0
        overall = round((detection.score or 0.0) * multiplier, 4)
        overall = max(0.0, min(1.0, overall))

        if impact is not None:
            limitations.extend(impact.limitations)
        limitations.append(
            "correlation and impact adjust prioritization only; they never establish maliciousness"
        )

        return RiskImpactScore(
            status="scored",
            candidate_ref=ref,
            gate_decision=decision,
            detection_risk=detection,
            business_impact=impact,
            overall_score=overall,
            overall_formula=(
                "overall = detection_risk * impact_multiplier; "
                "detection_risk = 0.60*rule_risk + 0.40*ml_risk (ml omitted if "
                "unavailable); impact_multiplier = business_impact when present else 1.0"
            ),
            alert_eligible=True,
            input_quality=input_quality,
            limitations=limitations,
        )

    def _detection_risk(
        self,
        evaluation: RuleEvaluation,
        ref: str,
        ml: MLService | None,
    ) -> tuple[DetectionRisk, list[str], list[str]]:
        """Compute detection risk from rules plus an optional ML ranking."""
        limitations: list[str] = []
        input_quality: list[str] = []
        rule_risk, signals, rule_limits = _rule_risk(evaluation)
        limitations.extend(rule_limits)
        input_quality.append(f"rule_findings={len(evaluation.findings)}")

        ml_risk: float | None = None
        ml_semantics: str | None = None
        if ml is not None:
            try:
                ml_result = ml.score(candidate_ref=ref, rule_evaluation=evaluation)
            except Exception as exc:  # noqa: BLE001 - never crash on ML
                limitations.append(f"ML scoring failed ({exc.__class__.__name__}): rules only")
                ml_result = None
            if ml_result is not None:
                input_quality.append(f"ml_status={ml_result.model_status}")
                if ml_result.model_status == "scored" and ml_result.model_score is not None:
                    ml_risk = ml_result.model_score
                    ml_semantics = ml_result.score_semantics
                else:
                    limitations.append(
                        f"ML model not applied ({ml_result.model_status}): "
                        "detection risk uses rules only"
                    )
        else:
            limitations.append("no ML service supplied: detection risk uses rules only")

        weights = {"rule": RULE_WEIGHT, "ml": ML_WEIGHT} if ml_risk is not None else {"rule": 1.0}
        if ml_risk is not None:
            score = RULE_WEIGHT * rule_risk + ML_WEIGHT * ml_risk
        else:
            score = rule_risk
        score = round(max(0.0, min(1.0, score)), 4)

        detection = DetectionRisk(
            score=score,
            formula=(
                "detection_risk = 0.60*rule_risk + 0.40*ml_risk; "
                "ml_risk omitted (weight->rule) when no trained model"
            ),
            rule_risk=rule_risk,
            ml_risk=ml_risk,
            ml_semantics=ml_semantics,
            weights=weights,
            signals=signals,
            limitations=["rule_risk is a severity-weighted mean of matched findings"]
            + limitations
            + ([ml_semantics] if ml_semantics else []),
        )
        return detection, limitations, input_quality

    def _business_impact(
        self,
        db: Session,
        request: RiskImpactRequest,
        decision: GateDecision,
    ) -> BusinessImpact:
        """Derive business impact only from genuine, available data."""
        signals: list[ContributingSignal] = []
        missing: list[str] = []
        limitations: list[str] = []
        total = 0.0

        # Stage 1: brand with verified assets is a genuine impact signal.
        brand_rows = db.execute(
            select(func.count(BrandAsset.id))
            .join(Brand, Brand.id == BrandAsset.brand_id)
            .where(BrandAsset.verified.is_(True))
        ).scalar()
        if brand_rows:
            contribution = min(0.4, 0.05 * brand_rows)
            total += contribution
            signals.append(
                ContributingSignal(
                    name="verified_brand_assets",
                    component="impact",
                    contribution=round(contribution, 4),
                    reason=f"{brand_rows} verified official brand asset(s) registered",
                    evidence_refs=["stage:1_brand_assets"],
                )
            )
        else:
            missing.append("no verified official brand assets registered (Stage 1)")

        # Stored reports referencing this exact target indicate real-world reach.
        reports = db.execute(
            select(func.count(Submission.id)).where(Submission.content == request.target)
        ).scalar()
        if reports:
            contribution = min(0.4, 0.05 * reports)
            total += contribution
            signals.append(
                ContributingSignal(
                    name="stored_reports",
                    component="impact",
                    contribution=round(contribution, 4),
                    reason=f"target referenced by {reports} stored submission(s)",
                    evidence_refs=[f"reports:{reports}"],
                )
            )
        else:
            missing.append("no stored submissions reference this target")

        # Stage 10 campaign context adjusts impact only, never detection.
        if request.campaign_context_size:
            contribution = min(0.2, 0.05 * request.campaign_context_size)
            total += contribution
            signals.append(
                ContributingSignal(
                    name="campaign_context",
                    component="impact",
                    contribution=round(contribution, 4),
                    reason=(
                        f"candidate linked to a campaign of "
                        f"{request.campaign_context_size} member(s) (context only)"
                    ),
                    evidence_refs=list(request.campaign_evidence_refs),
                )
            )
            limitations.append(
                "campaign context adjusts impact for prioritization only; "
                "correlation does not establish maliciousness"
            )
        else:
            missing.append("no campaign correlation context supplied (Stage 10)")

        # Genuine impact data we do NOT have and never invent.
        missing.extend(
            [
                "no reach/audience-size data (visitors, users, market share)",
                "no target-importance or business-criticality label",
                "no financial-exposure or monetization data",
            ]
        )

        if not signals:
            return BusinessImpact(
                status="unavailable",
                score=None,
                formula="business_impact unavailable: no genuine impact data present",
                missing_data=missing,
                limitations=[
                    "business impact could not be computed from available data; "
                    "overall score uses a neutral multiplier of 1.0 and reflects "
                    "detection risk only"
                ],
            )

        score = round(max(0.0, min(1.0, total)), 4)
        return BusinessImpact(
            status="available",
            score=score,
            formula=(
                "business_impact = min(1.0, sum of available signal contributions); "
                "contributions capped per signal (verified assets 0.05 each cap 0.4, "
                "reports 0.05 each cap 0.4, campaign 0.05 each cap 0.2)"
            ),
            signals=signals,
            missing_data=missing,
            limitations=limitations,
        )
