"""Analyzer B: brand and profile analysis (Stage 5).

Compares a candidate identity (handle/name/domain) against Stage 1 official
brand assets and produces explainable similarity signals.

Two distinct signal classes are kept separate:
- exact      a candidate value matches a registered asset byte-for-byte
             (case-insensitive) — high confidence, factual.
- heuristic  a candidate value merely resembles a registered asset via a
             documented ``difflib`` ratio — capped confidence, clearly labelled.

Heuristic similarity is NEVER presented as an exact match, and Stage 6 still
decides exclusion independently of this analyzer's observations.
"""

from __future__ import annotations

import difflib
from typing import Any

from app.schemas.evidence import AnalyzerResult
from sqlalchemy import select
from sqlalchemy.orm import Session

from risk_radar.db.models import Brand, BrandAsset
from risk_radar.evidence.base import (
    assessment_from_reasons,
    build_result,
    claimed_identity_observation,
    clamp_confidence,
    evidence_record,
)

# Documented heuristic thresholds (not secrets).
DOMAIN_SIMILARITY_THRESHOLD = 0.90
HANDLE_SIMILARITY_THRESHOLD = 0.85
NAME_SIMILARITY_THRESHOLD = 0.85


def _ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def _registrable(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _needle(kind: str, value: str) -> str:
    cleaned = value.strip().lower().rstrip(".")
    if kind == "handle":
        return cleaned if cleaned.startswith("@") else f"@{cleaned}"
    return cleaned


class BrandProfileAnalyzer:
    """Compare a candidate identity to Stage 1 official brand assets."""

    analyzer_type = "brand_profile"

    def analyze(
        self,
        db: Session,
        target: str,
        kind: str = "auto",
        input_id: str = "target",
        input_type: str = "social_profile",
        investigation_id: str = "unspecified",
    ) -> AnalyzerResult:
        """Inspect a candidate against registered brands; never declares safe."""
        raw = target.strip()
        if not raw:
            return build_result(
                analyzer_type="brand_profile",
                input_type=input_type,
                status="failed",
                input_id=input_id,
                investigation_id=investigation_id,
                errors=[{"stage": "normalize", "message": "empty target"}],
                limitations=["empty target: nothing to compare against brands"],
            )

        identity_kind, needle = self._identity(raw, kind)
        rows = db.execute(
            select(BrandAsset, Brand)
            .join(Brand, Brand.id == BrandAsset.brand_id)
            .order_by(BrandAsset.id)
        ).all()

        observations: list[dict[str, Any]] = []
        indicators: list[dict[str, Any]] = []
        evidence = [
            evidence_record(
                input_id,
                "identity",
                f"derived {identity_kind} identity '{needle}'",
                locator=raw[:2048],
                method="identity_derivation",
            )
        ]
        limitations: list[str] = []
        reason_codes: list[str] = []
        best_confidence: float | None = None

        observations.append(claimed_identity_observation(identity_kind, needle, 1.0))  # type: ignore[arg-type]

        if not rows:
            return build_result(
                analyzer_type="brand_profile",
                input_type=input_type,
                status="unavailable",
                input_id=input_id,
                locator=raw[:2048],
                investigation_id=investigation_id,
                observations=observations,
                evidence=evidence,
                assessment=assessment_from_reasons([]),
                limitations=[
                    "no official brand assets are registered: similarity cannot be "
                    "assessed and absence of data is NOT evidence of safety"
                ],
            )

        thresholds = {
            "domain": DOMAIN_SIMILARITY_THRESHOLD,
            "handle": HANDLE_SIMILARITY_THRESHOLD,
            "name": NAME_SIMILARITY_THRESHOLD,
        }
        threshold = thresholds.get(identity_kind, NAME_SIMILARITY_THRESHOLD)

        for asset, brand in rows:
            if asset.asset_type not in self._compatible_types(identity_kind):
                continue
            official = _needle(self._asset_kind(asset.asset_type), asset.value)
            candidate = needle
            if identity_kind == "domain":
                candidate, official = _registrable(needle), _registrable(asset.value)

            if candidate == official:
                indicators.append(
                    {
                        "kind": "exact_match",
                        "value": candidate,
                        "asset_id": asset.id,
                        "brand": brand.name,
                        "verified_asset": bool(asset.verified),
                        "severity": "high",
                        "confidence": 1.0,
                    }
                )
                evidence.append(
                    evidence_record(
                        input_id,
                        "brand_match",
                        f"exact match to {brand.name} {asset.asset_type} '{asset.value}'",
                        locator=asset.value,
                        method="exact_comparison",
                        asset_id=asset.id,
                        verified=asset.verified,
                    )
                )
                reason_codes.append("exact_match")
                best_confidence = 1.0
                continue

            score = _ratio(candidate, official)
            if score >= threshold:
                capped = clamp_confidence(score * 0.9)  # heuristic capped below exact
                indicators.append(
                    {
                        "kind": "heuristic_similarity",
                        "value": candidate,
                        "asset_id": asset.id,
                        "brand": brand.name,
                        "compared_to": official,
                        "similarity": round(score, 4),
                        "severity": "medium",
                        "confidence": capped,
                    }
                )
                evidence.append(
                    evidence_record(
                        input_id,
                        "brand_similarity",
                        f"heuristic similarity {score:.2f} to {brand.name} '{asset.value}'",
                        locator=asset.value,
                        method="difflib_ratio",
                        similarity=round(score, 4),
                    )
                )
                reason_codes.append("heuristic_similarity")
                if capped is not None and (best_confidence is None or capped > best_confidence):
                    best_confidence = capped

        if not reason_codes:
            limitations.append(
                f"no registered asset matched or resembled '{needle}' at the "
                f"documented thresholds; this is not a statement of safety"
            )

        return build_result(
            analyzer_type="brand_profile",
            input_type=input_type,
            status="completed",
            input_id=input_id,
            locator=raw[:2048],
            investigation_id=investigation_id,
            observations=observations,
            indicators=indicators,
            evidence=evidence,
            assessment=assessment_from_reasons(reason_codes, confidence=best_confidence),
            limitations=limitations,
        )

    @staticmethod
    def _identity(raw: str, kind: str) -> tuple[str, str]:
        if kind in {"domain", "handle", "name"}:
            return kind, _needle(kind, raw)
        if "://" in raw or ("." in raw and " " not in raw and not raw.startswith("@")):
            from urllib.parse import urlsplit

            host = None
            try:
                host = urlsplit(raw if "://" in raw else "//" + raw).hostname
            except ValueError:
                host = None
            if host:
                return "domain", _needle("domain", host)
        if raw.startswith("@"):
            return "handle", _needle("handle", raw)
        return "name", _needle("name", raw)

    @staticmethod
    def _asset_kind(asset_type: str) -> str:
        return {"domain": "domain", "account": "handle", "name": "name"}.get(asset_type, "name")

    @staticmethod
    def _compatible_types(identity_kind: str) -> set[str]:
        return {
            "domain": {"domain"},
            "handle": {"account"},
            "name": {"name"},
        }.get(identity_kind, {"name"})
