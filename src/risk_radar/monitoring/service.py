"""Bounded repeat-check runner and observation change detector."""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from risk_radar.core.config import get_settings
from risk_radar.db.models import (
    MonitoringAlert,
    MonitoringCheck,
    MonitoringObservation,
    MonitoringTarget,
)
from risk_radar.db.session import SessionLocal
from risk_radar.discovery.base import ConnectorError
from risk_radar.discovery.connectors.stubs import SocialPlatformConnector, SocialProfileProvider
from risk_radar.evidence.application import ApplicationListingAnalyzer
from risk_radar.evidence.brand_profile import BrandProfileAnalyzer
from risk_radar.evidence.resolvers import get_resolvers
from risk_radar.evidence.url_domain import UrlDomainAnalyzer
from risk_radar.gate.contracts import AnalyzerEvidence
from risk_radar.rules.engine import RuleEngine

# A scheduler task can be cancelled while its ``to_thread`` batch is still
# executing. Keep at most one batch in flight across lifespan restarts so a
# cancelled OS-level resolver cannot cause queued batches to accumulate.
_scheduler_batch_lock = threading.Lock()


class MonitorSignal(BaseModel):
    """A genuine normalized observation emitted by a provider or analyzer."""

    source: str
    kind: str
    key: str
    payload: dict[str, Any] = Field(default_factory=dict)
    alertable: bool = True


class MonitorCheckResult(BaseModel):
    """Provider outcome and observations from one target check."""

    status: str
    providers: dict[str, Any] = Field(default_factory=dict)
    observations: list[MonitorSignal] = Field(default_factory=list)
    complete_sources: list[str] = Field(default_factory=list)
    error: str | None = None


class MonitorChecker(Protocol):
    def check(self, target: MonitoringTarget, db: Session) -> MonitorCheckResult:
        """Run configured evidence providers for a persisted target."""


class ConfiguredEvidenceChecker:
    """Adapter from persisted target types to the existing evidence providers."""

    def __init__(self, social_provider: SocialProfileProvider | None = None) -> None:
        self.social_provider = social_provider

    def check(self, target: MonitoringTarget, db: Session) -> MonitorCheckResult:
        if target.target_type == "social_profile":
            return self._check_social(target, db)
        if target.target_type == "application":
            return self._check_application(target, db)
        return self._check_domain(target, db)

    def _check_social(self, target: MonitoringTarget, db: Session) -> MonitorCheckResult:
        connector = SocialPlatformConnector(provider=self.social_provider)
        try:
            candidates = connector.search(target.target)
        except ConnectorError as exc:
            provider_name = (
                self.social_provider.name if self.social_provider is not None else "social"
            )
            return MonitorCheckResult(
                status="unavailable",
                providers={provider_name: {"status": "unavailable", "error": str(exc)}},
                error=str(exc),
            )
        signals = []
        rule_snapshot_complete = True
        for candidate in candidates:
            metadata = dict(candidate.metadata)
            analysis = BrandProfileAnalyzer().analyze(
                db,
                candidate.target,
                kind="handle" if candidate.target.startswith("@") else "name",
                input_id=f"monitor:{target.id}:{candidate.candidate_id}",
                input_type="social_profile",
                brand_id=target.brand_id,
            )
            rules = RuleEngine().evaluate(
                db,
                candidate.target,
                kind="handle" if candidate.target.startswith("@") else "name",
                analysis=AnalyzerEvidence.model_validate(analysis.model_dump()),
                brand_id=target.brand_id,
            )
            if rules.status not in {"evaluated", "excluded_verified_official"}:
                rule_snapshot_complete = False
            profile_key = candidate.candidate_id
            signals.append(
                MonitorSignal(
                    source=candidate.source,
                    kind="discovered_profile",
                    key=profile_key,
                    payload={
                        "target": candidate.target,
                        "source_reference": candidate.source_reference,
                        "discovered_at": candidate.discovered_at.isoformat(),
                        "metadata": metadata,
                        "brand_profile_analysis": analysis.model_dump(mode="json"),
                    },
                )
            )
            for indicator in analysis.indicators:
                signals.append(
                    MonitorSignal(
                        source=candidate.source,
                        kind="profile_indicator",
                        key=(
                            f"{candidate.candidate_id}:{indicator['kind']}:"
                            f"{indicator.get('asset_id', '')}"
                        ),
                        payload={"profile": candidate.target, **indicator},
                    )
                )
            for finding in rules.findings:
                signals.append(
                    MonitorSignal(
                        source="rule_engine",
                        kind="rule_finding",
                        key=f"{candidate.candidate_id}:{finding.rule_id}",
                        payload={"profile": candidate.target, **finding.model_dump(mode="json")},
                    )
                )
        sources = sorted({candidate.source for candidate in candidates})
        # An empty response from a successfully completed provider is an authoritative snapshot.
        if not sources and self.social_provider is not None:
            sources = [self.social_provider.name]
        if rule_snapshot_complete:
            sources.append("rule_engine")
        return MonitorCheckResult(
            status="completed",
            providers={source: {"status": "completed"} for source in sources},
            observations=signals,
            complete_sources=sources,
        )

    def _check_application(self, target: MonitoringTarget, db: Session) -> MonitorCheckResult:
        result = ApplicationListingAnalyzer().analyze(
            db,
            target.target,
            input_id=f"monitor:{target.id}",
            input_type="app_listing",
            brand_id=target.brand_id,
        )
        provider = (
            "apple_itunes_lookup_api"
            if "apple" in target.target.lower() or target.target.isdecimal()
            else "google_play"
        )
        source_status = "completed" if result.status == "completed" else "unavailable"
        signals = _signals_from_analyzer(result.model_dump(mode="json"), provider)
        rules = RuleEngine().evaluate(
            db,
            target.target,
            kind="application",
            analysis=AnalyzerEvidence.model_validate(result.model_dump()),
            brand_id=target.brand_id,
        )
        signals.extend(
            MonitorSignal(
                source="rule_engine",
                kind="rule_finding",
                key=finding.rule_id,
                payload=finding.model_dump(mode="json"),
            )
            for finding in rules.findings
        )
        return MonitorCheckResult(
            status=result.status,
            providers={
                provider: {"status": source_status, "limitations": result.limitations},
                "rules": {"status": rules.status, "findings": len(rules.findings)},
            },
            observations=signals,
            complete_sources=(
                [provider, "rule_engine"]
                if source_status == "completed"
                and rules.status in {"evaluated", "excluded_verified_official"}
                else []
            ),
            error=None if result.status == "completed" else "; ".join(result.limitations),
        )

    def _check_domain(self, target: MonitoringTarget, db: Session) -> MonitorCheckResult:
        settings = get_settings()
        dns, rdap, redirects = get_resolvers(settings)
        analyzer = UrlDomainAnalyzer(dns=dns, rdap=rdap, redirects=redirects)
        url = target.target if "://" in target.target else f"https://{target.target}/"
        result = analyzer.analyze(url, input_id=f"monitor:{target.id}", input_type="url")
        signals = _signals_from_analyzer(result.model_dump(mode="json"), "url_evidence")
        rules = RuleEngine().evaluate(
            db,
            url,
            kind="domain",
            analysis=AnalyzerEvidence.model_validate(result.model_dump()),
            brand_id=target.brand_id,
        )
        signals.extend(
            MonitorSignal(
                source="rule_engine",
                kind="rule_finding",
                key=finding.rule_id,
                payload=finding.model_dump(mode="json"),
            )
            for finding in rules.findings
        )
        status = result.status
        return MonitorCheckResult(
            status=status,
            providers={
                "dns": {
                    "status": "completed"
                    if any(o.get("kind") == "dns_addresses" for o in result.observations)
                    else "unavailable"
                },
                "rdap": {
                    "status": "completed"
                    if any(o.get("kind") == "registration" for o in result.observations)
                    else "unavailable"
                },
                "redirects": {
                    "status": "disabled"
                    if not settings.evidence_enable_redirects
                    else "unavailable"
                },
                "analysis": {"status": status, "limitations": result.limitations},
                "rules": {"status": rules.status, "findings": len(rules.findings)},
            },
            observations=signals,
            # Domain absence is never inferred from a partial lookup. A full result is required.
            complete_sources=(
                ["url_evidence"]
                + [
                    source_name
                    for kind, source_name in (
                        ("dns_addresses", "dns_resolver"),
                        ("registration", "rdap_client"),
                        ("final_url", "redirect_checker"),
                    )
                    if any(observation.get("kind") == kind for observation in result.observations)
                ]
                + (
                    ["rule_engine"]
                    if rules.status in {"evaluated", "excluded_verified_official"}
                    else []
                )
                if status == "completed"
                else []
            ),
            error="; ".join(result.limitations) if status != "completed" else None,
        )


def _signals_from_analyzer(result: dict[str, Any], source: str) -> list[MonitorSignal]:
    signals: list[MonitorSignal] = []
    for observation in result.get("observations", []):
        kind = observation.get("kind")
        if kind in {"domain", "host", "registrable_domain"}:
            continue
        value = observation.get("value")
        if not isinstance(kind, str) or value is None:
            continue
        if kind == "store_listing_metadata":
            unique = "listing"
        elif kind in {"dns_addresses", "registration", "final_url"}:
            unique = kind
        else:
            unique = json.dumps(value, sort_keys=True, default=str)
        signals.append(
            MonitorSignal(
                source=str(observation.get("source") or observation.get("method") or source),
                kind=kind,
                key=unique,
                payload=observation,
                alertable=kind not in {"application"},
            )
        )
    for indicator in result.get("indicators", []):
        kind = indicator.get("kind")
        if not isinstance(kind, str):
            continue
        unique = f"{kind}:{indicator.get('value', '')}"
        signals.append(
            MonitorSignal(
                source=source,
                kind=f"indicator:{kind}",
                key=unique,
                payload=indicator,
            )
        )
    return signals


def _stable_json(value: Any) -> str:
    """Serialize evidence for comparison while ignoring retrieval-time churn."""
    volatile = {"retrieved_at", "discovered_at", "observed_at"}

    def strip_times(item: Any) -> Any:
        if isinstance(item, dict):
            return {key: strip_times(val) for key, val in item.items() if key not in volatile}
        if isinstance(item, list):
            return [strip_times(element) for element in item]
        return item

    return json.dumps(strip_times(value), sort_keys=True, separators=(",", ":"), default=str)


class MonitoringService:
    """Persist checks and state transitions with atomic per-target claiming."""

    def __init__(self, checker: MonitorChecker | None = None, clock=None) -> None:
        self.checker = checker or ConfiguredEvidenceChecker()
        self.clock = clock or (lambda: datetime.now(UTC))

    def run_check(self, db: Session, target_id: int, force: bool = True) -> MonitoringCheck | None:
        now = self.clock()
        target = db.get(MonitoringTarget, target_id)
        if target is None or target.removed or not target.enabled:
            return None
        stale_claim = now - timedelta(minutes=5)
        filters = [
            MonitoringTarget.id == target_id,
            MonitoringTarget.enabled.is_(True),
            MonitoringTarget.removed.is_(False),
            (
                MonitoringTarget.check_started_at.is_(None)
                | (MonitoringTarget.check_started_at < stale_claim)
            ),
        ]
        if not force:
            filters.append(MonitoringTarget.next_check_at <= now)
        claimed = db.execute(
            update(MonitoringTarget)
            .where(*filters)
            .values(check_started_at=now, last_status="running", last_error=None)
            .returning(MonitoringTarget.id)
            .execution_options(synchronize_session=False)
        ).scalar_one_or_none()
        db.commit()
        if claimed is None:
            return None
        target = db.get(MonitoringTarget, target_id)
        started_at = now
        try:
            result = self.checker.check(target, db)
        except Exception as exc:  # noqa: BLE001 - persist provider/analyzer failure state
            result = MonitorCheckResult(
                status="failed",
                error=f"check failed ({exc.__class__.__name__})",
                providers={"monitoring": {"status": "failed", "error": exc.__class__.__name__}},
            )
        finished_at = self.clock()
        check = MonitoringCheck(
            target_id=target_id,
            status=result.status,
            started_at=started_at,
            finished_at=finished_at,
            providers_json=json.dumps(result.providers, sort_keys=True, default=str),
            result_json=json.dumps(result.model_dump(mode="json"), sort_keys=True, default=str),
            error=result.error,
        )
        db.add(check)
        db.flush()
        changes = self._apply_changes(db, target_id, check, result, finished_at)
        result_payload = result.model_dump(mode="json")
        result_payload["changes"] = changes
        check.result_json = json.dumps(result_payload, sort_keys=True, default=str)
        target = db.get(MonitoringTarget, target_id)
        db.refresh(target)
        target.last_check_at = finished_at
        target.last_status = result.status
        target.last_error = result.error
        target.check_started_at = None
        target.next_check_at = (
            finished_at + timedelta(seconds=target.interval_seconds)
            if target.enabled and not target.removed
            else None
        )
        if result.status == "completed":
            target.last_success_at = finished_at
        target.updated_at = finished_at
        db.commit()
        db.refresh(check)
        return check

    @staticmethod
    def _apply_changes(
        db: Session,
        target_id: int,
        check: MonitoringCheck,
        result: MonitorCheckResult,
        now: datetime,
    ) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        existing_rows = list(
            db.scalars(
                select(MonitoringObservation).where(MonitoringObservation.target_id == target_id)
            )
        )
        existing = {row.observation_key: row for row in existing_rows}
        present: set[str] = set()
        for signal in result.observations:
            payload = signal.model_dump(mode="json")
            normalized = json.dumps(
                signal.payload, sort_keys=True, separators=(",", ":"), default=str
            )
            digest = hashlib.sha256(
                f"{signal.source}\0{signal.kind}\0{signal.key}".encode()
            ).hexdigest()
            present.add(digest)
            row = existing.get(digest)
            if row is None:
                row = MonitoringObservation(
                    target_id=target_id,
                    observation_key=digest,
                    source=signal.source,
                    payload_json=normalized,
                    active=True,
                    first_seen_at=now,
                    last_seen_at=now,
                    last_check_id=check.id,
                )
                db.add(row)
                db.flush()
                change = "new"
            else:
                old_payload = row.payload_json
                changed = _stable_json(json.loads(old_payload)) != _stable_json(signal.payload)
                was_active = row.active
                row.payload_json = normalized
                row.active = True
                row.last_seen_at = now
                row.last_check_id = check.id
                change = "changed" if changed else ("new" if not was_active else "unchanged")
            if signal.alertable and change in {"new", "changed"}:
                db.add(
                    MonitoringAlert(
                        target_id=target_id,
                        check_id=check.id,
                        observation_id=row.id,
                        change_type=change,
                        summary=f"{signal.kind.replace('_', ' ')} {change} for monitored target",
                        evidence_json=json.dumps(payload, sort_keys=True, default=str),
                    )
                )
            changes.append({"change_type": change, "observation_id": row.id, "signal": payload})
        if result.status == "completed" and result.complete_sources:
            completed_sources = set(result.complete_sources)
            for row in existing_rows:
                if (
                    row.active
                    and row.source in completed_sources
                    and row.observation_key not in present
                ):
                    row.active = False
                    row.last_check_id = check.id
                    db.add(
                        MonitoringAlert(
                            target_id=target_id,
                            check_id=check.id,
                            observation_id=row.id,
                            change_type="unavailable",
                            summary=(
                                "Previously observed evidence is absent from a complete "
                                "provider check"
                            ),
                            evidence_json=json.dumps(
                                {"previous_observation": json.loads(row.payload_json)}
                            ),
                        )
                    )
                    changes.append(
                        {
                            "change_type": "unavailable",
                            "observation_id": row.id,
                            "signal": {
                                "source": row.source,
                                "previous": json.loads(row.payload_json),
                            },
                        }
                    )
        # Provider outages make prior evidence unverifiable for this run, not absent.
        source_aliases = {
            "dns_resolver": "dns",
            "rdap_client": "rdap",
            "redirect_checker": "redirects",
            "apple_itunes_lookup_api": "apple_itunes_lookup_api",
            "rule_engine": "rules",
        }
        unavailable_states = {"unavailable", "disabled", "routed_to_verification", "failed_closed"}
        for row in existing_rows:
            provider_name = source_aliases.get(row.source)
            if provider_name is None and row.source in result.providers:
                provider_name = row.source
            if (
                provider_name is None
                and "social" in result.providers
                and row.source != "rule_engine"
            ):
                provider_name = "social"
            provider = result.providers.get(provider_name, {}) if provider_name else {}
            provider_status = provider.get("status") if isinstance(provider, dict) else None
            if row.active and provider_status in unavailable_states:
                changes.append(
                    {
                        "change_type": "unverifiable",
                        "observation_id": row.id,
                        "signal": {
                            "source": row.source,
                            "provider_status": provider_status,
                            "previous": json.loads(row.payload_json),
                        },
                    }
                )
        return changes

    def run_due(self, db: Session, limit: int = 10) -> list[int]:
        now = self.clock()
        targets = list(
            db.scalars(
                select(MonitoringTarget)
                .where(
                    MonitoringTarget.enabled.is_(True),
                    MonitoringTarget.removed.is_(False),
                    MonitoringTarget.next_check_at <= now,
                )
                .order_by(MonitoringTarget.next_check_at, MonitoringTarget.id)
                .limit(max(1, min(limit, 50)))
            )
        )
        completed: list[int] = []
        for target in targets:
            check = self.run_check(db, target.id, force=False)
            if check is not None:
                completed.append(check.id)
        return completed


def scheduler_batch(limit: int) -> None:
    """Run one bounded due batch using a short-lived database session."""
    with SessionLocal() as db:
        MonitoringService().run_due(db, limit=limit)


def try_claim_scheduler_batch() -> bool:
    """Claim the one scheduler slot before submitting work to an executor."""
    return _scheduler_batch_lock.acquire(blocking=False)


def release_scheduler_batch_claim() -> None:
    """Release a claim when executor submission itself fails."""
    _scheduler_batch_lock.release()


def run_claimed_scheduler_batch(limit: int) -> None:
    """Execute a claimed batch and release its slot even after task cancellation."""
    try:
        scheduler_batch(limit)
    finally:
        _scheduler_batch_lock.release()
