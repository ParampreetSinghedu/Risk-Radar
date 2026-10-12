
from uuid import uuid4

from pydantic import BaseModel, Field

from app.schemas.evidence import (
    AnalyzerResult,
    EvidenceRecord,
    SourceReference,
)


class BrandProfileAnalysisInput(BaseModel):
    investigation_id: str
    input_id: str
    profile_reference: str = Field(min_length=1)


def analyze_brand_profile(
    data: BrandProfileAnalysisInput,
) -> AnalyzerResult:
    source = SourceReference(
        input_id=data.input_id,
        kind="user_submission",
        locator=data.profile_reference,
    )

    evidence = EvidenceRecord(
        evidence_id=f"ev_{uuid4().hex[:8]}",
        evidence_type="brand_profile_observation",
        description=(
            "Brand/profile reference submitted for analysis: "
            f"{data.profile_reference}"
        ),
        source_reference=source,
        provenance={"source": "user_provided"},
        limitations=[
            "The profile reference has not been independently verified."
        ],
    )

    return AnalyzerResult(
        schema_version="1.0",
        investigation_id=data.investigation_id,
        analysis_id=f"ana_{uuid4().hex[:8]}",
        analyzer_type="brand_profile",
        input_type="brand_profile",
        status="partial",
        source_reference=source,
        evidence=[evidence],
        limitations=[
            "Only the submitted profile reference is recorded.",
            "No external profile checks or identity verification were performed.",
        ],
    )
