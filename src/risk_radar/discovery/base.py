"""Shared discovery connector contract and candidate record (Stage 3)."""

import hashlib
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, model_validator


class CandidateType(StrEnum):
    """Kinds of candidates discovery connectors can yield."""

    URL = "url"
    SOCIAL_PROFILE = "social_profile"
    APP_LISTING = "app_listing"


class DiscoveryError(Exception):
    """Base class for discovery connector errors."""


class ConnectorError(DiscoveryError):
    """A connector failed to produce results."""


class ConnectorUnavailableError(ConnectorError):
    """A connector cannot run because credentials or network access are missing."""


class ConnectorQueryError(ConnectorError):
    """The query is not usable by this connector."""


class ProvenanceEntry(BaseModel):
    """One discovery event for a candidate."""

    source: str
    source_reference: str
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def normalize_target(candidate_type: CandidateType, target: str) -> str:
    """Return the normalized identifier used to deduplicate candidates."""
    value = target.strip()
    if candidate_type in {CandidateType.URL, CandidateType.APP_LISTING}:
        try:
            parts = urlsplit(value)
        except ValueError:
            return value.lower()
        if parts.scheme and parts.netloc:
            path = "" if parts.path in {"", "/"} else parts.path
            query = f"?{parts.query}" if parts.query else ""
            return f"{parts.scheme.lower()}://{parts.netloc.lower()}{path}{query}"
        return value.lower()
    return value.lower().lstrip("@")


class Candidate(BaseModel):
    """Standard candidate record yielded by every discovery connector."""

    candidate_id: str = ""
    source: str = Field(min_length=1)
    source_reference: str = Field(min_length=1)
    candidate_type: CandidateType
    target: str = Field(min_length=1)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: list[ProvenanceEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _assign_id_and_provenance(self) -> "Candidate":
        """Derive a deterministic id and ensure provenance records the source."""
        normalized = normalize_target(self.candidate_type, self.target)
        payload = f"{self.candidate_type}:{normalized}".encode()
        self.candidate_id = hashlib.sha256(payload).hexdigest()[:16]
        if not self.provenance:
            self.provenance = [
                ProvenanceEntry(
                    source=self.source,
                    source_reference=self.source_reference,
                    discovered_at=self.discovered_at,
                )
            ]
        return self


class DiscoveryConnector(ABC):
    """Common interface implemented by every discovery connector."""

    name: ClassVar[str]

    @abstractmethod
    def search(self, query: str) -> list[Candidate]:
        """Return standard candidate records for the given query."""
