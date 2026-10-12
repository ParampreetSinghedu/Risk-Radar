"""Public introduction and judge pages are integrated with the existing UI."""

from fastapi.testclient import TestClient


def test_landing_and_project_pages_are_served_with_metadata(client: TestClient) -> None:
    landing = client.get("/")
    assert landing.status_code == 200
    assert "SentinelX — Evidence-led brand protection" in landing.text
    assert 'name="description"' in landing.text
    assert 'property="og:title"' in landing.text
    assert 'name="viewport"' in landing.text
    assert 'href="/site.css"' in landing.text
    assert 'href="/app?view=investigate"' in landing.text
    assert 'href="/project"' in landing.text
    assert "See the threat." in landing.text
    assert "Trace the evidence." in landing.text
    assert "Protect your brand." in landing.text

    project = client.get("/project")
    assert project.status_code == 200
    assert "Project Overview — SentinelX / Risk Radar" in project.text
    assert 'property="og:description"' in project.text
    assert "live-verified" in project.text
    assert "no live request was made" in project.text
    assert "DNS rebinding is eliminated" in project.text
    assert "Future scope · Not implemented" in project.text


def test_existing_dashboard_aliases_and_api_remain_available(client: TestClient) -> None:
    app_page = client.get("/app")
    dashboard_page = client.get("/dashboard")
    assert app_page.status_code == dashboard_page.status_code == 200
    assert 'id="view-investigate"' in app_page.text
    assert 'id="view-monitoring"' in app_page.text
    assert 'id="view-cases"' in app_page.text
    assert 'id="view-alerts"' in app_page.text
    assert 'id="inv-image"' in app_page.text
    assert 'id="inv-image-preview-img"' in app_page.text
    assert 'id="inv-image-remove"' in app_page.text
    assert 'id="inv-image-error"' in app_page.text
    assert 'id="inv-summary-inline"' in app_page.text
    assert 'id="inv-completion-dialog"' in app_page.text
    assert 'id="inv-completion-summary"' in app_page.text
    assert 'data-dashboard-view="investigate"' in app_page.text
    assert 'id="dash-monitoring"' in app_page.text
    assert 'href="/project"' in app_page.text
    assert "max-width: 820px" in app_page.text
    assert "max-width: 560px" in app_page.text
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/dashboard").status_code == 200
    assert client.get("/api/v1/monitoring/targets").status_code == 200
    assert client.get("/api/v1/monitoring/alerts?acknowledged=false").status_code == 200
    assert client.get("/api/v1/monitoring/status").status_code == 200
    assert client.get("/app.js").status_code == 200
    script = client.get("/app.js").text
    assert 'api("/evidence/analyze"' in script
    assert 'api("/submissions"' in script
    assert "Running investigation…" in script
    assert 'api("/monitoring/targets")' in script
    assert 'api("/monitoring/alerts?acknowledged=false")' in script
    assert 'api("/monitoring/status")' in script
    assert 'data-dashboard-view' in script
    assert "At a glance —" in script
    assert "Rule findings" in script
    assert "Analyzer observations" in script
    assert "Provider status and evidence gaps" in script
    assert (
        'showInvestigationCompletionDialog($("#inv-completion-dialog"), finalSummaryMarkup)'
        in script
    )
    assert 'summaryOut.innerHTML = summaryMarkup' in script
    assert 'setAttribute("aria-busy", "true")' in script
    assert "createImageBitmap(file)" in script
    assert client.get("/site.css").status_code == 200


def test_investigation_cta_selects_the_existing_dashboard_view(client: TestClient) -> None:
    app_page = client.get("/app?view=investigate")
    assert app_page.status_code == 200
    script = client.get("/app.js").text
    assert 'new URLSearchParams(window.location.search).get("view")' in script
    assert "if (requestedViewButton) requestedViewButton.click()" in script
    assert 'btn.dataset.view === requestedView' in script


def test_public_page_styles_include_responsive_and_reduced_motion_rules(client: TestClient) -> None:
    stylesheet = client.get("/site.css")
    assert stylesheet.status_code == 200
    assert "@media (max-width: 800px)" in stylesheet.text
    assert "@media (max-width: 560px)" in stylesheet.text
    assert "prefers-reduced-motion" in stylesheet.text
