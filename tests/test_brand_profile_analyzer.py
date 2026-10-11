
from app.analyzers.brand_profile_analyzer import (
    BrandProfileAnalysisInput,
    analyze_brand_profile,
)


def test_analyze_brand_profile_returns_partial_result():
    data = BrandProfileAnalysisInput(
        investigation_id="inv_test",
        input_id="input_test",
        profile_reference="https://example.com/brand",
    )

    result = analyze_brand_profile(data)

    assert result.analyzer_type == "brand_profile"
    assert result.input_type == "brand_profile"
    assert result.status == "partial"
    assert result.source_reference.locator == (
        "https://example.com/brand"
    )
    assert len(result.evidence) == 1
    assert (
        result.evidence[0].provenance["source"]
        == "user_provided"
    )

