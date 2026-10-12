"""Evaluation benchmark API endpoints (Stage 15).

Provides reproducibility benchmarks comparing rules and detection metrics
over structured synthetic evaluation samples.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from risk_radar.db.session import get_db
from risk_radar.evaluation.benchmark import BenchmarkReport, run_benchmark

router = APIRouter(tags=["evaluation"])


@router.get(
    "/evaluation/benchmark",
    response_model=BenchmarkReport,
    status_code=status.HTTP_200_OK,
    summary="Run synthetic evaluation benchmark",
)
def get_benchmark(
    db: Annotated[Session, Depends(get_db)],
    sample_limit: Annotated[int | None, Query(ge=1, le=100)] = None,
) -> BenchmarkReport:
    """Run the evaluation benchmark and return accuracy, precision, recall, and latency metrics."""
    return run_benchmark(db=db, sample_limit=sample_limit)
