"""Collection endpoint (Stage 4)."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from risk_radar.collection.service import CollectionResult, CollectionService

router = APIRouter(tags=["collection"])


def get_collection_service() -> CollectionService:
    """Build the collection service used by the collect endpoint."""
    return CollectionService()


class CollectRequest(BaseModel):
    """Candidate payloads handed to the collection layer."""

    candidates: list[Any] = Field(min_length=1)


@router.post("/collect", response_model=CollectionResult, summary="Collect candidates")
def collect(
    payload: CollectRequest,
    service: Annotated[CollectionService, Depends(get_collection_service)],
) -> CollectionResult:
    """Normalize, validate and deduplicate candidates into consistent records."""
    return service.collect(payload.candidates)
