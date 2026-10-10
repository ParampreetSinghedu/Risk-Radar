
from app.analyzers.image_analyzer import (
    ImageAnalysisInput,
    analyze_image,
)


def test_analyze_image_returns_partial_result():
    data = ImageAnalysisInput(
        investigation_id="inv_test",
        input_id="input_test",
        image_reference="uploads/sample.png",
    )

    result = analyze_image(data)

    assert result.analyzer_type == "image"
    assert result.input_type == "image"
    assert result.status == "partial"
    assert result.source_reference.locator == "uploads/sample.png"
    assert len(result.evidence) == 1
    assert result.evidence[0].provenance["source"] == "user_provided"