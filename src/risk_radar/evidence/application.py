"""App listing analysis with explicitly sourced store metadata.

Apple's public lookup endpoint is queried only for numeric App Store IDs. Android
package IDs are compared with registered assets but are not fetched: this project
has no authorized Google Play metadata API configured. User submitted data and
heuristic similarity are never described as store verified.
"""

from __future__ import annotations

import difflib
import re
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import parse_qs, urlsplit

import httpx
from app.schemas.evidence import AnalyzerResult
from sqlalchemy import select
from sqlalchemy.orm import Session

from risk_radar.db.models import Brand, BrandAsset
from risk_radar.evidence.base import assessment_from_reasons, build_result, evidence_record

_APPLE_LOOKUP = "https://itunes.apple.com/lookup"
_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*){1,}$")


class StoreLookup(Protocol):
    """Authorized metadata lookup for a parsed listing identifier."""

    def lookup(self, store: str, identifier: str) -> tuple[dict[str, Any] | None, str | None]:
        """Return verified metadata or an explicit limitation."""


class AppleStoreLookup:
    """Read metadata from Apple's official, unauthenticated lookup API."""

    def __init__(self, client: httpx.Client | None = None, timeout: float = 5.0) -> None:
        self.client = client
        self.timeout = timeout

    def lookup(self, store: str, identifier: str) -> tuple[dict[str, Any] | None, str | None]:
        if store != "apple_app_store" or not identifier.isdecimal():
            return None, "no authorized metadata lookup is configured for this listing identifier"
        try:
            if self.client is None:
                response = httpx.get(
                    _APPLE_LOOKUP,
                    params={"id": identifier},
                    timeout=self.timeout,
                    follow_redirects=False,
                )
            else:
                response = self.client.get(
                    _APPLE_LOOKUP,
                    params={"id": identifier},
                    timeout=self.timeout,
                    follow_redirects=False,
                )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError):
            return None, "Apple lookup source was unavailable or returned invalid data"
        if (
            not isinstance(payload, dict)
            or not isinstance(payload.get("results"), list)
            or not isinstance(payload.get("resultCount"), int)
        ):
            return None, "Apple lookup response did not contain a valid results collection"
        for item in payload["results"]:
            if isinstance(item, dict) and str(item.get("trackId")) == identifier:
                return item, None
        return None, "Apple lookup returned no listing matching the requested store ID"


class ApplicationListingAnalyzer:
    """Parse, optionally retrieve and compare app listing evidence."""

    analyzer_type = "application"

    def __init__(self, store_lookup: StoreLookup | None = None) -> None:
        self.store_lookup = store_lookup or AppleStoreLookup()

    def analyze(
        self,
        db: Session,
        target: str,
        input_id: str = "target",
        input_type: str = "app_listing",
        investigation_id: str = "unspecified",
        brand_id: int | None = None,
    ) -> AnalyzerResult:
        raw = target.strip()
        parsed = self._parse(raw)
        if parsed is None:
            return build_result(
                analyzer_type="application",
                input_type=input_type,
                status="partial",
                input_id=input_id,
                locator=raw[:2048],
                investigation_id=investigation_id,
                limitations=[
                    "listing identifier could not be extracted; provide an App Store URL or "
                    "package/bundle identifier"
                ],
            )
        store, identifier, listing_url = parsed
        observations: list[dict[str, Any]] = [
            {
                "kind": "application",
                "value": identifier,
                "store": store,
                "source": "user_submission",
                "verified": False,
            }
        ]
        evidence = [
            evidence_record(
                input_id,
                "submitted_application_identifier",
                f"application identifier supplied by user: {identifier}",
                locator=listing_url or raw[:2048],
                method="listing_identifier_parser",
                source="user_submission",
                verified=False,
            )
        ]
        limitations: list[str] = []
        try:
            metadata, limitation = self.store_lookup.lookup(store, identifier)
        except Exception as exc:  # noqa: BLE001 - provider errors become explicit coverage gaps
            metadata, limitation = (
                None,
                f"store metadata provider failed ({exc.__class__.__name__})",
            )
        if metadata is None:
            limitations.append(limitation or "store metadata is unavailable")
        else:
            retrieved_at = datetime.now(UTC).isoformat()
            store_fields = {
                "app_name": metadata.get("trackName"),
                "developer_name": metadata.get("sellerName"),
                "bundle_id": metadata.get("bundleId"),
                "store_listing_url": metadata.get("trackViewUrl"),
                "store_id": str(metadata.get("trackId")),
                "version": metadata.get("version"),
                "genre": metadata.get("primaryGenreName"),
            }
            store_fields = {k: v for k, v in store_fields.items() if isinstance(v, str) and v}
            observations.append(
                {
                    "kind": "store_listing_metadata",
                    "value": store_fields,
                    "store": store,
                    "source": "apple_itunes_lookup_api",
                    "retrieved_at": retrieved_at,
                    "verified": True,
                }
            )
            evidence.append(
                evidence_record(
                    input_id,
                    "store_listing_metadata",
                    "App Store metadata retrieved from Apple's official lookup API",
                    locator=_APPLE_LOOKUP + "?id=" + identifier,
                    method="apple_itunes_lookup_api",
                    source="apple_itunes_lookup_api",
                    retrieved_at=retrieved_at,
                    verified=True,
                    fields=store_fields,
                )
            )

        asset_query = (
            select(BrandAsset, Brand)
            .join(Brand, Brand.id == BrandAsset.brand_id)
            .where(BrandAsset.asset_type == "application")
            .order_by(BrandAsset.id)
        )
        if brand_id is not None:
            asset_query = asset_query.where(Brand.id == brand_id)
        rows = db.execute(asset_query).all()
        indicators: list[dict[str, Any]] = []
        reasons: list[str] = []
        for asset, brand in rows:
            expected = asset.value.strip().lower()
            actual = identifier.lower()
            verified = bool(asset.verified)
            if actual == expected:
                indicators.append(
                    {
                        "kind": "registered_application_match",
                        "asset_id": asset.id,
                        "brand": brand.name,
                        "verified_asset": verified,
                        "verification": "registered_asset_match"
                        if verified
                        else "unverified_registered_asset_match",
                        "severity": "informational",
                        "confidence": 1.0,
                    }
                )
                evidence.append(
                    evidence_record(
                        input_id,
                        "registered_application_match",
                        f"identifier exactly matches registered {brand.name} application asset",
                        locator=asset.value,
                        method="exact_identifier_comparison",
                        asset_id=asset.id,
                        verified_asset=verified,
                    )
                )
                reasons.append("registered_application_match")
                continue
            score = difflib.SequenceMatcher(None, actual, expected).ratio()
            if score >= 0.85:
                indicators.append(
                    {
                        "kind": "heuristic_application_similarity",
                        "asset_id": asset.id,
                        "brand": brand.name,
                        "compared_to": asset.value,
                        "similarity": round(score, 4),
                        "verified_asset": verified,
                        "severity": "informational",
                        "confidence": round(min(0.89, score * 0.85), 4),
                    }
                )
                evidence.append(
                    evidence_record(
                        input_id,
                        "heuristic_application_similarity",
                        f"submitted identifier resembles a registered {brand.name} "
                        "application identifier",
                        locator=asset.value,
                        method="difflib_ratio",
                        similarity=round(score, 4),
                        verified_asset=verified,
                    )
                )
                reasons.append("heuristic_application_similarity")
        if not rows:
            limitations.append(
                "no registered official application assets are available for comparison"
            )
        if store == "google_play" and metadata is None:
            limitations.append(
                "Google Play metadata retrieval is not configured; no listing details were verified"
            )
        return build_result(
            analyzer_type="application",
            input_type=input_type,
            status="completed" if metadata is not None else "partial",
            input_id=input_id,
            locator=listing_url or raw[:2048],
            investigation_id=investigation_id,
            observations=observations,
            indicators=indicators,
            evidence=evidence,
            assessment=assessment_from_reasons(reasons),
            limitations=limitations,
        )

    @staticmethod
    def _parse(value: str) -> tuple[str, str, str | None] | None:
        if not value:
            return None
        try:
            parts = urlsplit(value)
        except ValueError:
            return None
        if parts.scheme or parts.netloc:
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                return None
            host = parts.hostname.lower()
            if host == "play.google.com" and parts.path == "/store/apps/details":
                identifier = parse_qs(parts.query).get("id", [None])[0]
                if identifier and _PACKAGE_RE.fullmatch(identifier):
                    return "google_play", identifier, value
            if host in {"apps.apple.com", "itunes.apple.com"}:
                match = re.search(r"/id([^/]+)(?:/|$)", parts.path)
                if match:
                    identifier = match.group(1)
                    if identifier.isdecimal():
                        return "apple_app_store", identifier, value
            return None
        if _PACKAGE_RE.fullmatch(value):
            return "android_package", value, None
        if value.isdecimal():
            return "apple_app_store", value, None
        return None
