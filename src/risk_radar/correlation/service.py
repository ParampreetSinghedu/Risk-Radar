"""Evidence correlation over stored data and candidate targets (Stage 10).

Signals genuinely supported by existing data (documented, deterministic):

- ``duplicate_content``   identical target strings / stored content hashes (1.0)
- ``shared_domain``       same host (0.9) or same registrable domain (0.7)
- ``shared_brand``        submissions linked to the same Stage 1 brand (0.8)
- ``shared_brand_token``  a registered brand name appears in both targets (0.6)

Unsupported today and reported as such (never simulated): shared registrant
(WHOIS/RDAP data is unavailable) and shared logo/image indicators (image
evidence requires Stage 5 analyzers). Correlation never classifies
maliciousness: a relationship is context, not a verdict. Stage 6 outranks
correlation — verified official and unverified candidates never become
alert-eligible or join campaigns, and gate failures fail the whole request
closed.
"""

import hashlib
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from risk_radar.db.models import Brand, Submission
from risk_radar.gate.service import ExclusionGate

SIGNAL_STRENGTHS = {
    "duplicate_content": 1.0,
    "shared_domain": 0.9,
    "shared_domain_variant": 0.7,
    "shared_brand": 0.8,
    "shared_brand_token": 0.6,
}

UNSUPPORTED_SIGNALS = [
    "shared_registrant: WHOIS/RDAP registration data is unavailable in this stage",
    "shared_logo_publisher: image evidence requires Stage 5 analyzers (teammate-owned)",
]

GateOutcome = Literal["not_matched", "unverified", "verified_official"]


class CorrelationCandidate(BaseModel):
    """One candidate handed to the correlation service."""

    candidate_ref: str = Field(min_length=1, max_length=255)
    target: str = Field(min_length=1, max_length=2048)
    observed_at: datetime | None = None


class CandidateView(BaseModel):
    """Per-candidate correlation outcome, gated by Stage 6."""

    candidate_ref: str
    target: str
    gate_outcome: GateOutcome
    alert_eligible: bool
    campaign_id: str | None = None


class CorrelationLink(BaseModel):
    """One direct, explained relationship between two candidates."""

    source_ref: str
    target_ref: str
    signal: str
    reason: str
    strength: float = Field(ge=0, le=1)
    evidence_refs: list[str] = Field(default_factory=list)


class CampaignView(BaseModel):
    """A connected group of candidates with direct and indirect structure."""

    campaign_id: str
    candidate_refs: list[str]
    direct_links: list[CorrelationLink] = Field(default_factory=list)
    indirect_pairs: list[list[str]] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class TimelineEvent(BaseModel):
    """One chronological event from stored timestamps or provided observations."""

    occurred_at: datetime
    candidate_ref: str
    event: str
    evidence_ref: str


class CorrelationResult(BaseModel):
    """Full correlation output for one request."""

    schema_version: str = "1.0"
    status: Literal["completed", "failed_closed"]
    candidates: list[CandidateView] = Field(default_factory=list)
    links: list[CorrelationLink] = Field(default_factory=list)
    campaigns: list[CampaignView] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    unsupported_signals: list[str] = Field(default_factory=lambda: list(UNSUPPORTED_SIGNALS))
    limitations: list[str] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def _host(target: str) -> str | None:
    try:
        parts = urlsplit(target) if "://" in target else urlsplit(f"http://{target}")
    except ValueError:
        return None
    return parts.hostname.lower() if parts.hostname else None


def _registrable(host: str) -> str:
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _campaign_id(members: list[str]) -> str:
    return hashlib.sha256("|".join(sorted(members)).encode()).hexdigest()[:12]


class CorrelationService:
    """Group candidates into campaigns using only supported, explainable signals."""

    def correlate(self, db: Session, candidates: list[CorrelationCandidate]) -> CorrelationResult:
        """Correlate gate-eligible candidates into campaign views and a timeline."""
        ordered = sorted(candidates, key=lambda c: (c.candidate_ref, c.target))
        limitations: list[str] = []

        # Stage 6 first: authoritative gate decision per candidate.
        try:
            decisions = {
                candidate.candidate_ref: ExclusionGate().evaluate(db=db, target=candidate.target)
                for candidate in ordered
            }
        except Exception as exc:  # noqa: BLE001 - fail closed on any gate failure
            return CorrelationResult(
                status="failed_closed",
                limitations=[
                    f"gate decision unavailable ({exc.__class__.__name__}): "
                    "correlation failed closed"
                ],
            )

        views: dict[str, CandidateView] = {}
        eligible: list[CorrelationCandidate] = []
        for candidate in ordered:
            decision = decisions[candidate.candidate_ref]
            outcome = decision.outcome
            views[candidate.candidate_ref] = CandidateView(
                candidate_ref=candidate.candidate_ref,
                target=candidate.target,
                gate_outcome=outcome,  # type: ignore[arg-type]
                alert_eligible=decision.alert_eligible,
            )
            if outcome == "not_matched":
                eligible.append(candidate)
            else:
                limitations.append(
                    f"{candidate.candidate_ref}: excluded from correlation ({outcome})"
                )

        # Enrich eligible candidates from stored submissions (read-only).
        submissions_by_target: dict[str, list[Submission]] = {}
        all_targets = [c.target for c in eligible]
        if all_targets:
            rows = db.scalars(
                select(Submission)
                .where(Submission.content.in_(all_targets))
                .order_by(Submission.id)
            ).all()
            for submission in rows:
                submissions_by_target.setdefault(submission.content, []).append(submission)

        brand_names = {
            brand.name.lower(): brand.id
            for brand in db.scalars(select(Brand).order_by(Brand.id)).all()
            if len(brand.name) >= 4
        }

        links: list[CorrelationLink] = []
        for i, left in enumerate(eligible):
            for right in eligible[i + 1 :]:
                links.extend(self._pair_links(left, right, submissions_by_target, brand_names))

        campaigns = self._build_campaigns(links, eligible)
        campaign_by_ref = {
            ref: campaign.campaign_id for campaign in campaigns for ref in campaign.candidate_refs
        }
        for view in views.values():
            view.campaign_id = campaign_by_ref.get(view.candidate_ref)

        timeline, missing = self._build_timeline(ordered, submissions_by_target, views)
        if missing:
            limitations.append(
                f"{missing} candidate observation(s) omitted from the timeline: "
                "no timestamp provided or stored"
            )

        return CorrelationResult(
            status="completed",
            candidates=[views[ref] for ref in sorted(views)],
            links=links,
            campaigns=campaigns,
            timeline=timeline,
            limitations=limitations,
        )

    def _pair_links(
        self,
        left: CorrelationCandidate,
        right: CorrelationCandidate,
        submissions_by_target: dict[str, list[Submission]],
        brand_names: dict[str, int],
    ) -> list[CorrelationLink]:
        """Return every supported direct link between one candidate pair."""
        refs = [f"candidate:{left.candidate_ref}", f"candidate:{right.candidate_ref}"]
        links: list[CorrelationLink] = []

        if left.target == right.target:
            evidence = list(refs) + [
                f"submission:{submission.id}"
                for submission in submissions_by_target.get(left.target, [])
            ]
            links.append(
                CorrelationLink(
                    source_ref=left.candidate_ref,
                    target_ref=right.candidate_ref,
                    signal="duplicate_content",
                    reason="identical target content (duplicate evidence)",
                    strength=SIGNAL_STRENGTHS["duplicate_content"],
                    evidence_refs=evidence,
                )
            )

        left_host, right_host = _host(left.target), _host(right.target)
        if left_host and right_host:
            if left_host == right_host:
                links.append(
                    CorrelationLink(
                        source_ref=left.candidate_ref,
                        target_ref=right.candidate_ref,
                        signal="shared_domain",
                        reason=f"both candidates resolve to host '{left_host}'",
                        strength=SIGNAL_STRENGTHS["shared_domain"],
                        evidence_refs=list(refs),
                    )
                )
            elif _registrable(left_host) == _registrable(right_host):
                links.append(
                    CorrelationLink(
                        source_ref=left.candidate_ref,
                        target_ref=right.candidate_ref,
                        signal="shared_domain",
                        reason=(
                            f"hosts '{left_host}' and '{right_host}' share the "
                            f"registrable domain '{_registrable(left_host)}'"
                        ),
                        strength=SIGNAL_STRENGTHS["shared_domain_variant"],
                        evidence_refs=list(refs),
                    )
                )

        left_brands = {s.brand_id for s in submissions_by_target.get(left.target, []) if s.brand_id}
        right_brands = {
            s.brand_id for s in submissions_by_target.get(right.target, []) if s.brand_id
        }
        shared = sorted(left_brands & right_brands)
        if shared:
            brand_id = shared[0]
            evidence = (
                list(refs)
                + [f"brand:{brand_id}"]
                + [
                    f"submission:{s.id}"
                    for s in submissions_by_target[left.target]
                    + submissions_by_target[right.target]
                    if s.brand_id == brand_id
                ]
            )
            links.append(
                CorrelationLink(
                    source_ref=left.candidate_ref,
                    target_ref=right.candidate_ref,
                    signal="shared_brand",
                    reason=f"both candidates were submitted for brand:{brand_id}",
                    strength=SIGNAL_STRENGTHS["shared_brand"],
                    evidence_refs=evidence,
                )
            )

        token_matches = {
            name: brand_id
            for name, brand_id in brand_names.items()
            if name in left.target.lower() and name in right.target.lower()
        }
        if token_matches:
            name, brand_id = sorted(token_matches.items())[0]
            links.append(
                CorrelationLink(
                    source_ref=left.candidate_ref,
                    target_ref=right.candidate_ref,
                    signal="shared_brand_token",
                    reason=(
                        f"registered brand name '{name}' appears in both targets "
                        f"(possible shared impersonation theme)"
                    ),
                    strength=SIGNAL_STRENGTHS["shared_brand_token"],
                    evidence_refs=list(refs) + [f"brand:{brand_id}"],
                )
            )
        return links

    def _build_campaigns(
        self, links: list[CorrelationLink], eligible: list[CorrelationCandidate]
    ) -> list[CampaignView]:
        """Group connected components; keep direct links vs indirect pairs apart."""
        adjacency: dict[str, set[str]] = {}
        for link in links:
            adjacency.setdefault(link.source_ref, set()).add(link.target_ref)
            adjacency.setdefault(link.target_ref, set()).add(link.source_ref)

        campaigns: list[CampaignView] = []
        seen: set[str] = set()
        for candidate in sorted(eligible, key=lambda c: c.candidate_ref):
            root = candidate.candidate_ref
            if root in seen or root not in adjacency:
                continue
            component: set[str] = set()
            stack = [root]
            while stack:
                node = stack.pop()
                if node in component:
                    continue
                component.add(node)
                stack.extend(adjacency.get(node, ()))
            seen |= component

            members = sorted(component)
            direct = [
                link
                for link in links
                if link.source_ref in component and link.target_ref in component
            ]
            member_list = list(members)
            indirect = [
                [left, right]
                for i, left in enumerate(member_list)
                for right in member_list[i + 1 :]
                if not any({link.source_ref, link.target_ref} == {left, right} for link in direct)
            ]
            campaigns.append(
                CampaignView(
                    campaign_id=_campaign_id(members),
                    candidate_refs=members,
                    direct_links=direct,
                    indirect_pairs=indirect,
                )
            )

        for campaign in campaigns:
            times = [event.occurred_at for event in self._campaign_events(campaign, eligible)]
            if times:
                campaign.first_seen = min(times)
                campaign.last_seen = max(times)
        return campaigns

    def _campaign_events(
        self, campaign: CampaignView, eligible: list[CorrelationCandidate]
    ) -> list[TimelineEvent]:
        by_ref = {c.candidate_ref: c for c in eligible}
        events = []
        for ref in campaign.candidate_refs:
            candidate = by_ref.get(ref)
            if candidate is not None and candidate.observed_at is not None:
                events.append(
                    TimelineEvent(
                        occurred_at=candidate.observed_at,
                        candidate_ref=ref,
                        event="candidate_observed",
                        evidence_ref=f"candidate:{ref}",
                    )
                )
        return events

    def _build_timeline(
        self,
        ordered: list[CorrelationCandidate],
        submissions_by_target: dict[str, list[Submission]],
        views: dict[str, CandidateView],
    ) -> tuple[list[TimelineEvent], int]:
        """Chronological events from real stored/provided timestamps only."""
        events: list[TimelineEvent] = []
        missing = 0
        for candidate in ordered:
            view = views[candidate.candidate_ref]
            if view.gate_outcome != "not_matched":
                continue
            if candidate.observed_at is None:
                missing += 1
            else:
                events.append(
                    TimelineEvent(
                        occurred_at=candidate.observed_at,
                        candidate_ref=candidate.candidate_ref,
                        event="candidate_observed",
                        evidence_ref=f"candidate:{candidate.candidate_ref}",
                    )
                )
            for submission in submissions_by_target.get(candidate.target, []):
                events.append(
                    TimelineEvent(
                        occurred_at=submission.created_at,
                        candidate_ref=candidate.candidate_ref,
                        event="submission_stored",
                        evidence_ref=f"submission:{submission.id}",
                    )
                )
        events.sort(key=lambda event: (event.occurred_at, event.evidence_ref))
        return events, missing
