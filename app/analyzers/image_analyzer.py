
from uuid import uuid4

from pydantic import BaseModel, Field

from app.schemas.evidence import (
    AnalyzerResult,
    EvidenceRecord,
    SourceReference,
)


class ImageAnalysisInput(BaseModel):
    investigation_id: str
    input_id: str
    image_reference: str = Field(min_length=1)


def analyze_image(data: ImageAnalysisInput) -> AnalyzerResult:
    source = SourceReference(
        input_id=data.input_id,
        kind="user_submission",
        locator=data.image_reference,
    )

    evidence = EvidenceRecord(
        evidence_id=f"ev_{uuid4().hex[:8]}",
        evidence_type="image_observation",
        description=(
            f"Image reference submitted for analysis: "
            f"{data.image_reference}"
        ),
        source_reference=source,
        provenance={"source": "user_provided"},
        limitations=[
            "The image contents have not been inspected or verified."
        ],
    )

    return AnalyzerResult(
        schema_version="1.0",
        investigation_id=data.investigation_id,
        analysis_id=f"ana_{uuid4().hex[:8]}",
        analyzer_type="image",
        input_type="image",
        status="partial",
        source_reference=source,
        evidence=[evidence],
        limitations=[
            "Only the submitted image reference is recorded.",
            "No image content analysis has been performed.",
        ],
    )