"""Collection service: one consistent record from every source (Stage 4)."""

import hashlib
import re
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, ValidationError

from risk_radar.discovery.base import Candidate, CandidateType, ProvenanceEntry
from risk_radar.discovery.service import DiscoveryResult

_HANDLE = re.compile(r"^[A-Za-z0-9_.]{1,50}$")


def _parse_url(value: str):
    """Parse a URL, returning ``None`` when it is structurally unusable."""
    try:
        parts = urlsplit(value.strip())
        parts.port  # accessing .port validates it  # noqa: B018
    except ValueError:
        return None
    return parts


def clean_url(value: str) -> str:
    """Normalize an http(s) URL while preserving its meaningful information.

    Lowercases the scheme and host, removes default ports and fragments, and
    keeps userinfo, port, path and query exactly as submitted.
    """
    raw = value.strip()
    parts = _parse_url(raw)
    if parts is None or not parts.scheme or not parts.hostname:
        return raw
    scheme = parts.scheme.lower()
    userinfo = ""
    if "@" in parts.netloc:
        userinfo = parts.netloc.rsplit("@", 1)[0] + "@"
    host = parts.hostname.lower()
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    port = parts.port
    is_default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    port_text = f":{port}" if port is not None and not is_default_port else ""
    path = "" if parts.path == "/" else parts.path
    query = f"?{parts.query}" if parts.query else ""
    return f"{scheme}://{userinfo}{host}{port_text}{path}{query}"


def _looks_like_url(value: str) -> bool:
    return "://" in value


def url_errors(value: str) -> list[str]:
    """Return validation problems for an http(s) URL candidate target."""
    parts = _parse_url(value)
    if parts is None:
        return ["target is not a valid URL"]
    errors = []
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        errors.append("target must be an http(s) URL with a host")
    return errors


def validate_target(candidate_type: CandidateType, target: str) -> list[str]:
    """Return the validation problems for a candidate target, if any."""
    if not target.strip():
        return ["target must not be blank"]
    if candidate_type == CandidateType.URL:
        return url_errors(target)
    if candidate_type == CandidateType.SOCIAL_PROFILE:
        if _looks_like_url(target):
            return url_errors(target)
        handle = target.strip()
        if not handle.startswith("@") or not _HANDLE.fullmatch(handle[1:]):
            return ["target must be an http(s) URL or an @handle"]
        return []
    # APP_LISTING: a store URL is validated as a URL; other text stays free-form.
    if _looks_like_url(target):
        return url_errors(target)
    return []


def normalize_target(candidate_type: CandidateType, target: str) -> str:
    """Return the cleaned identifier used for consistent records and dedup."""
    value = target.strip()
    if candidate_type in {CandidateType.URL, CandidateType.APP_LISTING}:
        if _looks_like_url(value):
            return clean_url(value)
        return value.lower()
    if _looks_like_url(value):
        return clean_url(value)
    handle = value.lstrip("@")
    return f"@{handle.lower()}"


class CollectedRecord(BaseModel):
    """One consistent, source-attributed record produced by collection."""

    record_id: str
    candidate_type: CandidateType
    original_target: str
    normalized_target: str
    sources: list[str] = Field(default_factory=list)
    source_references: list[str] = Field(default_factory=list)
    provenance: list[ProvenanceEntry] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    validation_status: Literal["valid", "invalid"] = "valid"
    validation_errors: list[str] = Field(default_factory=list)


class CollectionError(BaseModel):
    """Structured error for input that could not become a record."""

    index: int | None = None
    source: str
    error_type: Literal["malformed", "connector_error"]
    reason: str


class CollectionResult(BaseModel):
    """Output of one collection run: records plus structured errors."""

    records: list[CollectedRecord] = Field(default_factory=list)
    errors: list[CollectionError] = Field(default_factory=list)


def _source_of(item: Any) -> str:
    """Best-effort source extraction for error reporting."""
    if isinstance(item, Candidate):
        return item.source
    if isinstance(item, dict):
        source = item.get("source")
        return source if isinstance(source, str) and source else "unknown"
    return "unknown"


def _merge(existing: CollectedRecord, incoming: CollectedRecord) -> None:
    """Merge an equivalent incoming record, preserving all attribution."""
    for source in incoming.sources:
        if source not in existing.sources:
            existing.sources.append(source)
    for reference in incoming.source_references:
        if reference not in existing.source_references:
            existing.source_references.append(reference)
    for entry in incoming.provenance:
        if entry not in existing.provenance:
            existing.provenance.append(entry)
    for key, value in incoming.metadata.items():
        existing.metadata.setdefault(key, value)
    if incoming.collected_at < existing.collected_at:
        existing.collected_at = incoming.collected_at
    if incoming.validation_status == "invalid":
        existing.validation_status = "invalid"
        for problem in incoming.validation_errors:
            if problem not in existing.validation_errors:
                existing.validation_errors.append(problem)


class CollectionService:
    """Normalize, validate and deduplicate candidates from any source."""

    def collect(self, items: list[Any]) -> CollectionResult:
        """Turn mixed candidate inputs into consistent records, isolating bad input."""
        result = CollectionResult()
        by_id: dict[str, CollectedRecord] = {}
        for index, item in enumerate(items):
            try:
                candidate = item if isinstance(item, Candidate) else Candidate.model_validate(item)
            except (ValidationError, TypeError, ValueError) as exc:
                errors = exc.errors() if isinstance(exc, ValidationError) else []
                reason = (
                    "; ".join(
                        f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}"
                        for err in errors
                    )
                    or "input is not a valid candidate"
                )
                result.errors.append(
                    CollectionError(
                        index=index,
                        source=_source_of(item),
                        error_type="malformed",
                        reason=reason,
                    )
                )
                continue

            problems = validate_target(candidate.candidate_type, candidate.target)
            normalized = normalize_target(candidate.candidate_type, candidate.target)
            record = CollectedRecord(
                record_id=hashlib.sha256(
                    f"{candidate.candidate_type}:{normalized}".encode()
                ).hexdigest()[:16],
                candidate_type=candidate.candidate_type,
                original_target=candidate.target,
                normalized_target=normalized,
                sources=[candidate.source],
                source_references=[candidate.source_reference],
                provenance=list(candidate.provenance),
                metadata=dict(candidate.metadata),
                collected_at=datetime.now(UTC),
                validation_status="invalid" if problems else "valid",
                validation_errors=problems,
            )
            existing = by_id.get(record.record_id)
            if existing is None:
                by_id[record.record_id] = record
            else:
                _merge(existing, record)
        result.records = list(by_id.values())
        return result

    def collect_discovery(self, discovery: DiscoveryResult) -> CollectionResult:
        """Collect a discovery result, carrying connector failures through as errors."""
        result = self.collect(list(discovery.candidates))
        for failure in discovery.failures:
            result.errors.append(
                CollectionError(
                    index=None,
                    source=failure.source,
                    error_type="connector_error",
                    reason=failure.reason,
                )
            )
        return result
