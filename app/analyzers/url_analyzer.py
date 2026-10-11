from uuid import uuid4
from pydantic import BaseModel

from app.schemas.evidence import (
    AnalyzerResult,
    EvidenceRecord,
    SourceReference,
)


class URLAnalysisInput(BaseModel):
    investigation_id: str
    input_id: str
    original_url: str


def analyze_url(data: URLAnalysisInput) -> AnalyzerResult:
    source = SourceReference(
        input_id=data.input_id,
        kind="user_submission",
        locator=data.original_url,
    )

    evidence = EvidenceRecord(
        evidence_id=f"ev_{uuid4().hex[:8]}",
        evidence_type="url_observation",
        description=f"URL submitted for analysis: {data.original_url}",
        source_reference=source,
        provenance={"source": "user_provided"},
    )

    return AnalyzerResult(
        schema_version="1.0",
        investigation_id=data.investigation_id,
        analysis_id=f"ana_{uuid4().hex[:8]}",
        analyzer_type="url",
        input_type="url",
        status="partial",
        source_reference=source,
        evidence=[evidence],
        limitations=[
            "Only the submitted URL is recorded; no external URL checks have been performed."
        ],
    )

