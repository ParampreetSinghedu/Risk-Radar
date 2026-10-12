"""Read-only investigation tools (Stage 9).

All tools are read-only: they search stored evidence and existing discovery
connectors. Retrieved web content is validated and treated strictly as data;
nothing in it is ever executed or obeyed as instructions.
"""

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from risk_radar.collection.service import url_errors
from risk_radar.db.models import Brand, BrandAsset, ExclusionAuditLog, Submission
from risk_radar.discovery.base import Candidate, DiscoveryConnector
from risk_radar.discovery.service import DiscoveryService, default_connectors
from risk_radar.investigator.contracts import EvidenceHit, ResearchHit

_MAX_EVIDENCE_HITS = 20
_MAX_RESEARCH_HITS = 10


def search_stored_evidence(db: Session, query: str) -> list[EvidenceHit]:
    """Search submissions, brand assets and audit entries; strictly read-only."""
    needle = f"%{query.strip().lower()}%"
    hits: list[EvidenceHit] = []

    submissions = db.scalars(
        select(Submission)
        .where(func.lower(Submission.content).like(needle))
        .order_by(Submission.id)
        .limit(_MAX_EVIDENCE_HITS)
    ).all()
    for submission in submissions:
        hits.append(
            EvidenceHit(
                reference=f"submission:{submission.id}",
                kind="submission",
                summary=f"{submission.submission_type}: {submission.content[:160]}",
            )
        )

    assets = db.execute(
        select(BrandAsset, Brand)
        .join(Brand, Brand.id == BrandAsset.brand_id)
        .where(func.lower(BrandAsset.value).like(needle))
        .order_by(BrandAsset.id)
        .limit(_MAX_EVIDENCE_HITS)
    ).all()
    for asset, brand in assets:
        hits.append(
            EvidenceHit(
                reference=f"brand_asset:{asset.id}",
                kind="brand_asset",
                summary=f"{brand.name} {asset.asset_type}: {asset.value}",
            )
        )

    audit_entries = db.scalars(
        select(ExclusionAuditLog)
        .where(func.lower(ExclusionAuditLog.input_reference).like(needle))
        .order_by(ExclusionAuditLog.id)
        .limit(_MAX_EVIDENCE_HITS)
    ).all()
    for entry in audit_entries:
        hits.append(
            EvidenceHit(
                reference=f"audit_log:{entry.id}",
                kind="audit_log",
                summary=f"gate {entry.decision}: {entry.input_reference[:120]}",
            )
        )
    return hits


def web_research(
    query: str, connectors: list[DiscoveryConnector] | None = None
) -> tuple[list[ResearchHit], list[str]]:
    """Run web research through the existing discovery connectors.

    Returns validated research hits and limitations. Connector failures and
    malformed results become limitations — never silent, never instructions.
    """
    registry = connectors if connectors is not None else default_connectors()
    service = DiscoveryService(registry)
    discovery = service.discover(query)
    limitations = [f"{failure.source}: {failure.reason}" for failure in discovery.failures]

    hits: list[ResearchHit] = []
    skipped = 0
    for candidate in discovery.candidates[:_MAX_RESEARCH_HITS]:
        if not isinstance(candidate, Candidate) or url_errors(candidate.target):
            skipped += 1
            continue
        hits.append(
            ResearchHit(
                reference=f"{candidate.source}:{candidate.target}",
                source=candidate.source,
                url=candidate.target,
                summary=str(candidate.metadata.get("snippet") or candidate.metadata)[:3000],
                retrieved_at=candidate.discovered_at or datetime.now(UTC),
                title=candidate.metadata.get("title"),
                snippet=candidate.metadata.get("snippet"),
                content_kind=candidate.metadata.get("content_kind", "provider_record"),
                page_content_retrieved=bool(
                    candidate.metadata.get("page_content_retrieved", False)
                ),
                search_query=candidate.metadata.get("query"),
            )
        )
    if skipped:
        limitations.append(f"{skipped} research result(s) skipped: invalid URL")
    if not hits and not limitations:
        limitations.append("web research returned no results for this query")
    return hits, limitations
