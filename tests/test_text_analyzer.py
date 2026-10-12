from app.analyzers.text_analyzer import (
    TextAnalysisInput,
    analyze_text,
)


def test_analyze_text_returns_partial_result():
    data = TextAnalysisInput(
        investigation_id="inv_test",
        input_id="input_test",
        submitted_text="Please verify this suspicious message.",
    )

    result = analyze_text(data)

    assert result.analyzer_type == "text"
    assert result.input_type == "text"
    assert result.status == "partial"
    assert result.source_reference.locator == "text_input:input_test"
    assert len(result.evidence) == 1
    assert result.evidence[0].provenance["source"] == "user_provided"
