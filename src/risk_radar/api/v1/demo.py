"""Demo data management API (Stage 15).

Provides idempotent seeding for triage simulation and presentation walkthroughs.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from risk_radar.db.session import get_db
from risk_radar.demo.seeder import DemoSeedSummary, seed_demo_data

router = APIRouter(tags=["demo"])


@router.post(
    "/demo/seed",
    response_model=DemoSeedSummary,
    status_code=status.HTTP_200_OK,
    summary="Seed demo data idempotently",
)
def run_seed(db: Annotated[Session, Depends(get_db)]) -> DemoSeedSummary:
    """Populate official brands, assets, user submissions, cases, and reviews."""
    return seed_demo_data(db)
