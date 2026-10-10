"""Brand intelligence endpoints (Stage 1)."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from risk_radar.db.models import AssetType, Brand, BrandAsset
from risk_radar.db.session import get_db

router = APIRouter(tags=["brands"])


class BrandCreate(BaseModel):
    """Payload used to create an official brand profile."""

    name: str = Field(min_length=1, max_length=255)


class BrandResponse(BaseModel):
    """Brand profile returned to clients."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    created_at: datetime


class BrandAssetCreate(BaseModel):
    """Payload used to register an official brand asset."""

    asset_type: AssetType
    value: str = Field(min_length=1)
    verified: bool = False


class BrandAssetResponse(BaseModel):
    """Brand asset together with its verification state."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    brand_id: int
    asset_type: AssetType
    value: str
    verified: bool
    created_at: datetime


def _get_brand(db: Session, brand_id: int) -> Brand:
    """Return the brand or raise a 404 when it does not exist."""
    brand = db.get(Brand, brand_id)
    if brand is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Brand not found")
    return brand


@router.post(
    "/brands",
    response_model=BrandResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a brand profile",
)
def create_brand(payload: BrandCreate, db: Annotated[Session, Depends(get_db)]) -> Brand:
    """Store an official brand profile identified by its canonical name."""
    existing = db.scalar(select(Brand).where(Brand.name == payload.name))
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Brand already exists")
    brand = Brand(name=payload.name)
    db.add(brand)
    db.commit()
    db.refresh(brand)
    return brand


@router.get("/brands/{brand_id}", response_model=BrandResponse, summary="Read a brand profile")
def read_brand(brand_id: int, db: Annotated[Session, Depends(get_db)]) -> Brand:
    """Return a single brand profile by identifier."""
    return _get_brand(db, brand_id)


@router.post(
    "/brands/{brand_id}/assets",
    response_model=BrandAssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a brand asset",
)
def create_asset(
    brand_id: int, payload: BrandAssetCreate, db: Annotated[Session, Depends(get_db)]
) -> BrandAsset:
    """Attach an official asset to a brand, marking it verified or unverified."""
    _get_brand(db, brand_id)
    asset = BrandAsset(
        brand_id=brand_id,
        asset_type=payload.asset_type.value,
        value=payload.value,
        verified=payload.verified,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.get(
    "/brands/{brand_id}/assets",
    response_model=list[BrandAssetResponse],
    summary="List brand assets",
)
def list_assets(brand_id: int, db: Annotated[Session, Depends(get_db)]) -> list[BrandAsset]:
    """Return every official asset registered for a brand."""
    _get_brand(db, brand_id)
    assets = db.scalars(
        select(BrandAsset).where(BrandAsset.brand_id == brand_id).order_by(BrandAsset.id)
    ).all()
    return list(assets)
