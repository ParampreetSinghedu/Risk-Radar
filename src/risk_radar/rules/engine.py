"""Deterministic rule engine with exclusion-gate enforcement (Stage 7).

Documented thresholds (module constants, not secrets):

- ``LOOKALIKE_SIMILARITY_THRESHOLD``: minimum ``difflib`` ratio between the
  candidate registrable domain and an official domain for a lookalike hit.
- ``USERNAME_SIMILARITY_THRESHOLD``: minimum ratio between a candidate handle
  and official handles/brand names.
- ``NEW_DOMAIN_THRESHOLD_DAYS``: maximum registration age for the
  newly-registered-domain rule, evaluated only when the analyzer supplies
  explicit registration data.

Every matched finding states its reason, observed/expected values and
evidence references. Missing data yields a skipped rule, never a match.
"""

import difflib
import ipaddress
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from risk_radar.db.models import Brand, BrandAsset
from risk_radar.gate.contracts import AnalyzerEvidence, usable_observations
from risk_radar.gate.service import ExclusionGate, GateDecision, extract_identity

LOOKALIKE_SIMILARITY_THRESHOLD = 0.90
USERNAME_SIMILARITY_THRESHOLD = 0.85
NEW_DOMAIN_THRESHOLD_DAYS = 90
_SEVERITY = Literal["informational", "low", "medium", "high", "critical"]
EvalStatus = Literal[
    "evaluated",
    "excluded_verified_official",
    "routed_to_verification",
    "failed_closed",
]


class RuleFinding(BaseModel):
    """One matched rule with a stated reason and traceable evidence."""

    rule_id: str
    title: str
    matched: bool = True
    severity: _SEVERITY
    reason: str
    evidence_refs: list[str] = Field(default_factory=list)
    observed_value: str | None = None
    expected_value: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    provenance: dict[str, Any] = Field(default_factory=dict)


class RuleNote(BaseModel):
    """Non-match or skipped rule with its stated reason."""

    rule_id: str
    title: str
    status: Literal["not_matched", "skipped"]
    reason: str


class RuleEvaluation(BaseModel):
    """Deterministic evaluation output for one candidate."""

    schema_version: str = "1.0"
    status: EvalStatus
    candidate_ref: str
    gate_decision: GateDecision | None = None
    findings: list[RuleFinding] = Field(default_factory=list)
    not_matched: list[RuleNote] = Field(default_factory=list)
    skipped: list[RuleNote] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    limitations: list[str] = Field(default_factory=list)
    errors: list[dict[str, str]] = Field(default_factory=list)


class RuleContext(BaseModel):
    """Inputs shared by all rules for one evaluation."""

    target: str
    kind: str
    host: str | None
    official_domains: list[dict[str, Any]] = Field(default_factory=list)
    official_handles: list[dict[str, Any]] = Field(default_factory=list)
    official_names: list[str] = Field(default_factory=list)
    observations: list[dict[str, Any]] = Field(default_factory=list)


def _ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def _registrable(host: str) -> str:
    """Approximate the registrable domain (last two labels; documented limit)."""
    labels = host.lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def rule_lookalike_domain(context: RuleContext) -> RuleFinding | RuleNote:
    """R1: official brand/domain embedded in or similar to another domain."""
    if context.kind != "domain" or not context.host:
        return RuleNote(
            rule_id="lookalike_domain",
            title="Lookalike domain indicators",
            status="skipped",
            reason="candidate is not a domain",
        )
    if not context.official_domains and not context.official_names:
        return RuleNote(
            rule_id="lookalike_domain",
            title="Lookalike domain indicators",
            status="skipped",
            reason="no official domains or brand names registered to compare against",
        )
    if _is_ip(context.host):
        return RuleNote(
            rule_id="lookalike_domain",
            title="Lookalike domain indicators",
            status="skipped",
            reason="host is an IP literal; no domain string to compare",
        )

    host = context.host.lower()
    candidate_reg = _registrable(host)
    labels = host.split(".")

    for official in context.official_domains:
        official_value = str(official["value"]).lower()
        official_reg = _registrable(official_value)
        refs = ["target", f"brand_asset:{official['id']}"]
        if candidate_reg == official_reg and host != official_value:
            return RuleFinding(
                rule_id="lookalike_domain",
                title="Lookalike domain indicators",
                severity="medium",
                reason=(
                    f"host '{host}' is under official domain '{official_value}' "
                    "but is not the registered official asset itself"
                ),
                evidence_refs=refs,
                observed_value=host,
                expected_value=official_value,
                confidence=1.0,
                provenance={"method": "exact_registrable_domain_comparison"},
            )
        score = _ratio(candidate_reg, official_reg)
        if score >= LOOKALIKE_SIMILARITY_THRESHOLD and candidate_reg != official_reg:
            return RuleFinding(
                rule_id="lookalike_domain",
                title="Lookalike domain indicators",
                severity="high",
                reason=(
                    f"domain '{candidate_reg}' resembles official '{official_reg}' "
                    f"with similarity {score:.2f} >= {LOOKALIKE_SIMILARITY_THRESHOLD}"
                ),
                evidence_refs=refs,
                observed_value=candidate_reg,
                expected_value=official_reg,
                confidence=score,
                provenance={"method": "difflib.SequenceMatcher.ratio"},
            )

    names = [name.lower() for name in context.official_names if len(name) >= 4]
    for name in names:
        for label in labels:
            hit = (
                label == name
                or f"{name}-" in label
                or f"-{name}" in label
                or label.startswith(name)
                and label != name
                and label[len(name)] in "-_"
            )
            if hit and candidate_reg != name:
                official_domain = next(
                    (
                        d["value"]
                        for d in context.official_domains
                        if name in str(d["value"]).lower()
                    ),
                    None,
                )
                return RuleFinding(
                    rule_id="lookalike_domain",
                    title="Lookalike domain indicators",
                    severity="high",
                    reason=(
                        f"official brand name '{name}' appears in host label "
                        f"'{label}' on a domain that is not the official asset"
                    ),
                    evidence_refs=["target"],
                    observed_value=host,
                    expected_value=official_domain,
                    confidence=1.0,
                    provenance={"method": "brand_token_in_host_label"},
                )
    return RuleNote(
        rule_id="lookalike_domain",
        title="Lookalike domain indicators",
        status="not_matched",
        reason="no lookalike indicators against registered official assets",
    )


def rule_username_similarity(context: RuleContext) -> RuleFinding | RuleNote:
    """R2: candidate handle similar to official handles or brand names."""
    if context.kind != "handle":
        return RuleNote(
            rule_id="username_similarity",
            title="Brand or username similarity",
            status="skipped",
            reason="candidate is not a profile handle",
        )
    if not context.official_handles and not context.official_names:
        return RuleNote(
            rule_id="username_similarity",
            title="Brand or username similarity",
            status="skipped",
            reason="no official handles or brand names registered to compare against",
        )
    candidate = context.target.lower().lstrip("@")
    best_score = 0.0
    best_expected: str | None = None
    for official in context.official_handles:
        expected = str(official["value"]).lower().lstrip("@")
        score = _ratio(candidate, expected)
        if score > best_score and candidate != expected:
            best_score, best_expected = score, f"@{expected}"
    for name in context.official_names:
        score = _ratio(candidate, name.lower())
        if score > best_score and candidate != name.lower():
            best_score, best_expected = score, name.lower()
    if best_expected is None or best_score < USERNAME_SIMILARITY_THRESHOLD:
        return RuleNote(
            rule_id="username_similarity",
            title="Brand or username similarity",
            status="not_matched",
            reason=(
                f"closest official identity '{best_expected}' is below the "
                f"similarity threshold {USERNAME_SIMILARITY_THRESHOLD}"
                if best_expected
                else "no comparable official identity differs from the candidate"
            ),
        )
    return RuleFinding(
        rule_id="username_similarity",
        title="Brand or username similarity",
        severity="medium",
        reason=(
            f"handle '@{candidate}' resembles official '{best_expected}' "
            f"with similarity {best_score:.2f} >= {USERNAME_SIMILARITY_THRESHOLD}"
        ),
        evidence_refs=["target"],
        observed_value=f"@{candidate}",
        expected_value=best_expected,
        confidence=best_score,
        provenance={"method": "difflib.SequenceMatcher.ratio"},
    )


def rule_ip_host(context: RuleContext) -> RuleFinding | RuleNote:
    """R3a: the URL host is a raw IP address."""
    if context.kind != "domain" or not context.host:
        return RuleNote(
            rule_id="ip_host",
            title="IP-address host",
            status="skipped",
            reason="candidate has no host to inspect",
        )
    if _is_ip(context.host):
        return RuleFinding(
            rule_id="ip_host",
            title="IP-address host",
            severity="medium",
            reason=f"URL host '{context.host}' is a raw IP address instead of a domain name",
            evidence_refs=["target"],
            observed_value=context.host,
            confidence=1.0,
            provenance={"method": "ipaddress.ip_address"},
        )
    return RuleNote(
        rule_id="ip_host",
        title="IP-address host",
        status="not_matched",
        reason="host is a domain name, not an IP literal",
    )


def rule_suspicious_url_structure(context: RuleContext) -> RuleFinding | RuleNote:
    """R3b: documented structural URL anomalies (credentials, punycode, ports...)."""
    if context.kind != "domain":
        return RuleNote(
            rule_id="suspicious_url_structure",
            title="Suspicious URL structure",
            status="skipped",
            reason="candidate is not a URL",
        )
    hits: list[str] = []
    try:
        parts = urlsplit(context.target) if "://" in context.target else None
    except ValueError:
        parts = None
    if parts is not None:
        if parts.username or parts.password:
            hits.append("credentials embedded in the URL (userinfo)")
        if parts.hostname:
            if any(label.startswith("xn--") for label in parts.hostname.split(".")):
                hits.append("punycode (internationalized) host label")
            if len(parts.hostname.split(".")) >= 5:
                hits.append("five or more subdomain labels")
            if parts.port is not None and parts.port not in {80, 443}:
                hits.append(f"non-standard port {parts.port}")
    if hits:
        return RuleFinding(
            rule_id="suspicious_url_structure",
            title="Suspicious URL structure",
            severity="medium",
            reason="; ".join(hits),
            evidence_refs=["target"],
            observed_value=context.target,
            confidence=1.0,
            provenance={"method": "url_structure_check"},
        )
    return RuleNote(
        rule_id="suspicious_url_structure",
        title="Suspicious URL structure",
        status="not_matched",
        reason="no structural anomalies in the configured checks",
    )


def rule_newly_registered_domain(context: RuleContext) -> RuleFinding | RuleNote:
    """R4: matches only when explicit registration data is actually present."""
    for observation in context.observations:
        if observation.get("kind") != "domain_age_days":
            continue
        age = observation.get("value")
        if not isinstance(age, int) or isinstance(age, bool):
            continue
        if age <= NEW_DOMAIN_THRESHOLD_DAYS:
            return RuleFinding(
                rule_id="newly_registered_domain",
                title="Newly registered domain",
                severity="medium",
                reason=(
                    f"domain registration age {age} day(s) is within the "
                    f"{NEW_DOMAIN_THRESHOLD_DAYS}-day threshold"
                ),
                evidence_refs=["target", "analysis"],
                observed_value=str(age),
                expected_value=f"<= {NEW_DOMAIN_THRESHOLD_DAYS} days",
                confidence=1.0,
                provenance={"method": "analyzer_registration_observation"},
            )
        return RuleNote(
            rule_id="newly_registered_domain",
            title="Newly registered domain",
            status="not_matched",
            reason=(
                f"registration age {age} day(s) exceeds the "
                f"{NEW_DOMAIN_THRESHOLD_DAYS}-day threshold"
            ),
        )
    return RuleNote(
        rule_id="newly_registered_domain",
        title="Newly registered domain",
        status="skipped",
        reason=(
            "no WHOIS/RDAP registration data available: "
            "rule cannot evaluate without it and missing data is not a match"
        ),
    )


def rule_logo_publisher_mismatch(context: RuleContext) -> RuleFinding | RuleNote:
    """R5: matches only on an explicit analyzer logo/publisher observation."""
    for observation in context.observations:
        if observation.get("kind") != "logo_mismatch":
            continue
        observed_publisher = observation.get("observed_publisher")
        expected_publisher = observation.get("expected_publisher")
        if not observed_publisher or not expected_publisher:
            continue
        return RuleFinding(
            rule_id="logo_publisher_mismatch",
            title="Logo used by a different publisher",
            severity="high",
            reason=(
                f"logo observed on publisher '{observed_publisher}' does not match "
                f"official publisher '{expected_publisher}'"
            ),
            evidence_refs=["target", "analysis"],
            observed_value=str(observed_publisher),
            expected_value=str(expected_publisher),
            confidence=1.0,
            provenance={"method": "analyzer_logo_observation"},
        )
    return RuleNote(
        rule_id="logo_publisher_mismatch",
        title="Logo used by a different publisher",
        status="skipped",
        reason="no explicit logo/publisher evidence provided by analyzers",
    )


RULE_REGISTRY = [
    rule_lookalike_domain,
    rule_username_similarity,
    rule_ip_host,
    rule_suspicious_url_structure,
    rule_newly_registered_domain,
    rule_logo_publisher_mismatch,
]


def _build_context(
    db: Session,
    target: str,
    kind: str,
    analysis: AnalyzerEvidence | None,
) -> tuple[RuleContext, list[str]]:
    """Load Stage 1 official assets and usable analyzer observations."""
    identity_kind, needle = extract_identity(target, kind)  # type: ignore[arg-type]
    host: str | None = None
    if "://" in target:
        try:
            host = urlsplit(target).hostname
        except ValueError:
            host = None
    if host is None and identity_kind == "domain":
        host = needle

    rows = db.execute(
        select(BrandAsset, Brand)
        .join(Brand, Brand.id == BrandAsset.brand_id)
        .order_by(BrandAsset.id)
    ).all()
    official_domains = [
        {"id": asset.id, "value": asset.value, "brand": brand.name}
        for asset, brand in rows
        if asset.asset_type == "domain"
    ]
    official_handles = [
        {"id": asset.id, "value": asset.value}
        for asset, brand in rows
        if asset.asset_type == "account"
    ]
    official_names = sorted(
        {brand.name for _, brand in rows}
        | {asset.value for asset, _ in rows if asset.asset_type == "name"}
    )

    if analysis is not None:
        observations, limitations = usable_observations(analysis)
    else:
        observations, limitations = [], []

    context = RuleContext(
        target=target,
        kind=identity_kind,
        host=host,
        official_domains=official_domains,
        official_handles=official_handles,
        official_names=official_names,
        observations=observations,
    )
    return context, limitations


class RuleEngine:
    """Run the deterministic registry only for gate-eligible candidates."""

    def evaluate(
        self,
        db: Session,
        target: str,
        kind: str = "auto",
        analysis: AnalyzerEvidence | None = None,
        candidate_ref: str | None = None,
    ) -> RuleEvaluation:
        """Evaluate rules after an authoritative, server-side gate decision."""
        ref = (candidate_ref or target)[:255]
        try:
            decision = ExclusionGate().evaluate(
                db=db,
                target=target,
                kind=kind,
                analysis=analysis,  # type: ignore[arg-type]
            )
        except Exception as exc:  # noqa: BLE001 - fail closed on any gate failure
            return RuleEvaluation(
                status="failed_closed",
                candidate_ref=ref,
                errors=[{"stage": "exclusion_gate", "message": exc.__class__.__name__}],
                limitations=[
                    "gate decision unavailable: evaluation failed closed and no rules ran"
                ],
            )

        if decision.outcome == "verified_official":
            return RuleEvaluation(
                status="excluded_verified_official",
                candidate_ref=ref,
                gate_decision=decision,
                limitations=["verified official asset excluded by Stage 6; rules were not run"],
            )
        if decision.outcome == "unverified":
            return RuleEvaluation(
                status="routed_to_verification",
                candidate_ref=ref,
                gate_decision=decision,
                limitations=[
                    "unverified identity held for verification/review by Stage 6; "
                    "rules were not run"
                ],
            )

        context, analysis_limitations = _build_context(db, target, kind, analysis)
        findings: list[RuleFinding] = []
        not_matched: list[RuleNote] = []
        skipped: list[RuleNote] = []
        errors: list[dict[str, str]] = []
        for rule in RULE_REGISTRY:
            rule_id = getattr(rule, "__name__", "unknown_rule")
            try:
                outcome = rule(context)
            except Exception as exc:  # noqa: BLE001 - isolate rule failures
                errors.append(
                    {"stage": "rule", "rule_id": rule_id, "message": exc.__class__.__name__}
                )
                continue
            if isinstance(outcome, RuleFinding):
                findings.append(outcome)
            elif outcome.status == "skipped":
                skipped.append(outcome)
            else:
                not_matched.append(outcome)

        return RuleEvaluation(
            status="evaluated",
            candidate_ref=ref,
            gate_decision=decision,
            findings=findings,
            not_matched=not_matched,
            skipped=skipped,
            limitations=list(decision.limitations) + analysis_limitations,
            errors=errors,
        )
