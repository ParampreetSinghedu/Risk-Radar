"""Modular retrieval interface and stored-evidence retriever (Stage 12).

Retrieval is pluggable via the ``Retriever`` protocol. The default
``StoredEvidenceRetriever`` queries the existing Stage 2/6 tables (submissions,
brand assets, exclusion-audit log) with plain relevance scoring.

No pgvector or embedding store exists in this project, so no vector/semantic
retrieval is claimed; relevance here is a deterministic lexical-overlap score.
Every returned document carries a stable ``doc_id``, its source locator and a
retrieval timestamp so later citations are traceable.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from risk_radar.db.models import Brand, BrandAsset, ExclusionAuditLog, Submission
from risk_radar.rag.contracts import RetrievedDocument

_MAX_DOCS = 20


class Retriever(Protocol):
    """Retrieve stored evidence relevant to one candidate target."""

    def retrieve(self, db: Session, target: str) -> list[RetrievedDocument]: ...


def _relevance(text: str, terms: set[str]) -> float:
    """Deterministic lexical-overlap relevance in [0, 1]."""
    if not terms:
        return 0.0
    lowered = text.lower()
    hits = sum(1 for term in terms if term in lowered)
    return round(hits / len(terms), 4)


def _terms(target: str) -> set[str]:
    """Derive meaningful search terms from a target (host + path tokens)."""
    cleaned = target.strip().lower()
    for prefix in ("http://", "https://"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
    tokens = {part for part in cleaned.replace("/", " ").replace(".", " ").split() if len(part) > 2}
    if cleaned and len(cleaned) > 2:
        tokens.add(cleaned)
    return tokens


class StoredEvidenceRetriever:
    """Retrieve from the existing stored-evidence tables (read-only)."""

    def retrieve(self, db: Session, target: str) -> list[RetrievedDocument]:
        """Return ranked stored documents relevant to ``target``."""
        terms = _terms(target)
        needle = f"%{target.strip().lower()}%"
        docs: list[RetrievedDocument] = []
        now = datetime.now(UTC)

        submissions = (
            db.scalars(
                select(Submission)
                .where(
                    (Submission.content.ilike(needle))
                    | (Submission.content.ilike(f"%{_host_like(target)}%"))
                )
                .order_by(Submission.id)
                .limit(_MAX_DOCS)
            ).all()
            if _host_like(target)
            else db.scalars(
                select(Submission)
                .where(Submission.content.ilike(needle))
                .order_by(Submission.id)
                .limit(_MAX_DOCS)
            ).all()
        )
        for submission in submissions:
            docs.append(
                RetrievedDocument(
                    doc_id=f"submission:{submission.id}",
                    source_type="submission",
                    locator=submission.content[:2048],
                    content=f"{submission.submission_type}: {submission.content[:400]}",
                    relevance=_relevance(submission.content, terms),
                    retrieved_at=now,
                    provenance={
                        "submission_id": submission.id,
                        "source": submission.source,
                        "brand_id": submission.brand_id,
                        "created_at": submission.created_at.isoformat(),
                    },
                )
            )

        assets = db.execute(
            select(BrandAsset, Brand)
            .join(Brand, Brand.id == BrandAsset.brand_id)
            .order_by(BrandAsset.id)
            .limit(_MAX_DOCS)
        ).all()
        for asset, brand in assets:
            relevance = _relevance(f"{brand.name} {asset.value}", terms)
            if relevance <= 0.0:
                continue
            docs.append(
                RetrievedDocument(
                    doc_id=f"brand_asset:{asset.id}",
                    source_type="brand_asset",
                    locator=asset.value,
                    content=f"{brand.name} {asset.asset_type}: {asset.value}",
                    relevance=relevance,
                    retrieved_at=now,
                    provenance={
                        "asset_id": asset.id,
                        "brand_id": brand.id,
                        "verified": asset.verified,
                    },
                )
            )

        audit_entries = db.scalars(
            select(ExclusionAuditLog)
            .where(ExclusionAuditLog.input_reference.ilike(needle))
            .order_by(ExclusionAuditLog.id.desc())
            .limit(1)
        ).all()
        # An audit row records a gate decision, not independent evidence.
        # Repeated pipeline reads can create many equivalent rows; retain at
        # most the latest one, and let substantive submissions/assets take
        # precedence when any are available.
        if not any(doc.source_type != "audit_log" for doc in docs):
            for entry in audit_entries:
                docs.append(
                    RetrievedDocument(
                        doc_id=f"audit_log:{entry.id}",
                        source_type="audit_log",
                        locator=entry.input_reference,
                        content=f"gate {entry.decision}: {entry.reason[:300]}",
                        relevance=_relevance(entry.input_reference, terms),
                        retrieved_at=now,
                        provenance={
                            "audit_id": entry.id,
                            "decision": entry.decision,
                            "alert_eligible": entry.alert_eligible,
                        },
                    )
                )

        # Deterministic ranking: relevance desc, then doc_id for stable ties.
        docs.sort(key=lambda d: (-d.relevance, d.doc_id))
        return docs[:_MAX_DOCS]


def _host_like(target: str) -> str:
    """Best-effort host fragment used to widen submission matching."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(target if "://" in target else f"http://{target}")
        return parts.hostname or ""
    except ValueError:
        return ""
