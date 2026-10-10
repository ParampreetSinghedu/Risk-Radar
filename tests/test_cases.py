"""Stage 13 — Cases, dashboard, alerts and reports tests.

Covers case creation (with server-side gate), workflow transitions, analyst
events, report generation, dashboard summary, gate safety (verified official
never alert-eligible) and static dashboard serving. No network or external
services are required.
"""

from __future__ import annotations

from risk_radar.db.models import Brand, BrandAsset


def _register_brand(session, name, assets, verify_first=False):
    brand = Brand(name=name)
    session.add(brand)
    session.flush()
    for asset_type, value in assets:
        session.add(
            BrandAsset(brand_id=brand.id, asset_type=asset_type, value=value, verified=verify_first)
        )
    session.commit()


def _session_from_client(client):
    from risk_radar.db.session import get_db

    return next(client.app.dependency_overrides[get_db]())


# --- case creation & gate -------------------------------------------------


def test_create_case_returns_201_with_gate_outcome(client):
    r = client.post(
        "/api/v1/cases",
        json={"title": "Test", "target": "http://192.0.2.9/x"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "open"
    assert body["gate_outcome"] in {"not_matched", "unverified", "verified_official"}
    # alert eligibility is exactly the not_matched outcome, nothing else
    assert body["alert_eligible"] is (body["gate_outcome"] == "not_matched")


def test_create_case_verified_official_never_alert_eligible(client):
    session = _session_from_client(client)
    _register_brand(session, "PayPal", [("domain", "paypal.com")], verify_first=True)
    r = client.post(
        "/api/v1/cases",
        json={"title": "Official", "target": "https://paypal.com/login", "kind": "auto"},
    )
    body = r.json()
    assert body["gate_outcome"] == "verified_official"
    assert body["alert_eligible"] is False


def test_create_case_unverified_routed_not_eligible(client):
    session = _session_from_client(client)
    _register_brand(session, "PayPal", [("domain", "paypal.com")], verify_first=False)
    r = client.post(
        "/api/v1/cases",
        json={"title": "Unverified", "target": "https://paypal.com/login", "kind": "auto"},
    )
    body = r.json()
    assert body["gate_outcome"] == "unverified"
    assert body["alert_eligible"] is False


def test_create_case_rejects_missing_fields(client):
    assert client.post("/api/v1/cases", json={"title": "x"}).status_code == 422
    assert client.post("/api/v1/cases", json={"target": "http://x"}).status_code == 422


# --- listing & reading ----------------------------------------------------


def test_list_and_read_case(client):
    created = client.post("/api/v1/cases", json={"title": "A", "target": "http://192.0.2.1"}).json()
    listed = client.get("/api/v1/cases").json()
    assert any(c["id"] == created["id"] for c in listed)
    read = client.get(f"/api/v1/cases/{created['id']}").json()
    assert read["title"] == "A"
    assert read["events"]  # opening event recorded


def test_list_cases_filter_by_status(client):
    created = client.post("/api/v1/cases", json={"title": "A", "target": "http://192.0.2.1"}).json()
    client.patch(f"/api/v1/cases/{created['id']}/status", json={"status": "closed"})
    open_cases = client.get("/api/v1/cases?case_status=open").json()
    closed_cases = client.get("/api/v1/cases?case_status=closed").json()
    assert created["id"] not in [c["id"] for c in open_cases]
    assert created["id"] in [c["id"] for c in closed_cases]


def test_read_missing_case_404(client):
    assert client.get("/api/v1/cases/99999").status_code == 404


# --- workflow & analyst events --------------------------------------------


def test_status_transition_records_event(client):
    cid = client.post("/api/v1/cases", json={"title": "A", "target": "http://192.0.2.1"}).json()[
        "id"
    ]
    r = client.patch(
        f"/api/v1/cases/{cid}/status", json={"status": "in_review", "note": "triaging"}
    )
    body = r.json()
    assert body["status"] == "in_review"
    assert any(e["event_type"] == "status_change" for e in body["events"])


def test_add_analyst_decision_event(client):
    cid = client.post("/api/v1/cases", json={"title": "A", "target": "http://192.0.2.1"}).json()[
        "id"
    ]
    r = client.post(
        f"/api/v1/cases/{cid}/events",
        json={"event_type": "decision", "note": "confirmed phishing", "actor": "alice"},
    )
    body = r.json()
    assert any(e["note"] == "confirmed phishing" and e["actor"] == "alice" for e in body["events"])


def test_invalid_status_422(client):
    cid = client.post("/api/v1/cases", json={"title": "A", "target": "http://192.0.2.1"}).json()[
        "id"
    ]
    r = client.patch(f"/api/v1/cases/{cid}/status", json={"status": "bogus"})
    assert r.status_code == 422


# --- reports --------------------------------------------------------------


def test_case_report_uses_real_data_only(client):
    cid = client.post(
        "/api/v1/cases", json={"title": "Rep", "target": "http://192.0.2.1", "note": "why"}
    ).json()["id"]
    r = client.get(f"/api/v1/cases/{cid}/report")
    body = r.json()
    assert r.status_code == 200
    assert body["title"] == "Rep"
    assert body["report_sections"]
    # snapshot absent -> limitation, not fabricated
    assert body["snapshot_available"] is False
    assert any("snapshot" in lim for lim in body["limitations"])


def test_case_report_with_snapshot(client):
    cid = client.post(
        "/api/v1/cases",
        json={
            "title": "Rep",
            "target": "http://192.0.2.1",
            "snapshot": {"rules": {"status": "evaluated"}},
        },
    ).json()["id"]
    body = client.get(f"/api/v1/cases/{cid}/report").json()
    assert body["snapshot_available"] is True
    assert body["snapshot"]["rules"]["status"] == "evaluated"


def test_missing_report_404(client):
    assert client.get("/api/v1/cases/99999/report").status_code == 404


# --- dashboard ------------------------------------------------------------


def test_dashboard_empty_state(client):
    body = client.get("/api/v1/dashboard").json()
    assert body["total_cases"] == 0
    assert body["recent_cases"] == []
    assert body["data_available"] is True


def test_dashboard_aggregates_real_counts(client):
    for i in range(3):
        client.post("/api/v1/cases", json={"title": f"C{i}", "target": f"http://192.0.2.{i + 1}"})
    body = client.get("/api/v1/dashboard").json()
    assert body["total_cases"] == 3
    assert body["open_cases"] == 3
    assert len(body["recent_cases"]) == 3


# --- alerts view ----------------------------------------------------------


def test_alerts_excludes_official_and_unverified(client):
    session = _session_from_client(client)
    _register_brand(session, "PayPal", [("domain", "paypal.com")], verify_first=True)
    _register_brand(session, "Acme", [("domain", "acme.com")], verify_first=False)
    client.post(
        "/api/v1/cases", json={"title": "Off", "target": "https://paypal.com", "kind": "auto"}
    )
    client.post(
        "/api/v1/cases", json={"title": "Unv", "target": "https://acme.com", "kind": "auto"}
    )
    client.post("/api/v1/cases", json={"title": "Real", "target": "http://192.0.2.50/x"})
    cases = client.get("/api/v1/cases").json()
    eligible = [c for c in cases if c["alert_eligible"]]
    assert len(eligible) == 1
    assert eligible[0]["title"] == "Real"


# --- static dashboard -----------------------------------------------------


def test_dashboard_html_is_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Risk Radar" in r.text


def test_app_js_is_served(client):
    r = client.get("/app.js")
    assert r.status_code == 200
    assert "api/v1" in r.text
