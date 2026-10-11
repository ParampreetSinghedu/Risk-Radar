from app.analyzers.url_analyzer import URLAnalysisInput, analyze_url


def test_analyze_url_returns_partial_result():
    data = URLAnalysisInput(
        investigation_id="inv_test",
        input_id="input_test",
        original_url="https://example.com",
    )

    result = analyze_url(data)

    assert result.analyzer_type == "url"
    assert result.input_type == "url"
    assert result.status == "partial"
    assert result.source_reference.locator == "https://example.com"
    assert len(result.evidence) == 1
    assert result.evidence[0].provenance["source"] == "user_provided"
