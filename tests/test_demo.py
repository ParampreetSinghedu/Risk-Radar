"""Tests for Stage 15 Demo Data Seeding."""

import json

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from risk_radar.db.base import Base
from risk_radar.db.models import Case, CaseEvent, CaseStatus, HumanReview, ReviewVerdict
from risk_radar.demo.seeder import SYNTHETIC_PROVENANCE, seed_demo_data


def test_seed_demo_data_endpoint(client: TestClient) -> None:
    """The demo seeding endpoint must populate synthetic brands, cases, and reviews."""
    resp = client.post("/api/v1/demo/seed")
    assert resp.status_code == 200
    data = resp.json()

    assert data["is_synthetic"] is True
    assert "synthetic demo data" in data["disclaimer"].lower()
    assert data["brands_created"] >= 3
    assert data["cases_created"] == 7
    assert data["reviews_created"] >= 2


def test_demo_seeder_is_idempotent(client: TestClient) -> None:
    """Running the demo seeder multiple times must not crash or duplicate unique constraints."""
    first_resp = client.post("/api/v1/demo/seed")
    assert first_resp.status_code == 200

    second_resp = client.post("/api/v1/demo/seed")
    assert second_resp.status_code == 200
    second_data = second_resp.json()
    assert second_data["is_synthetic"] is True
    assert second_data["cases_created"] == 0


def test_seeded_data_populates_dashboard_and_cases(client: TestClient) -> None:
    """Seeded demo cases must reflect immediately in dashboard metrics and case listings."""
    client.post("/api/v1/demo/seed")

    dash_resp = client.get("/api/v1/dashboard")
    assert dash_resp.status_code == 200
    dash = dash_resp.json()

    assert dash["total_cases"] >= 3
    assert dash["open_cases"] >= 1
    assert dash["in_review_cases"] >= 1
    assert dash["closed_cases"] >= 1
    assert len(dash["recent_cases"]) >= 3

    cases_resp = client.get("/api/v1/cases")
    assert cases_resp.status_code == 200
    cases = cases_resp.json()
    assert len(cases) == 7

    expected_targets = {
        "https://paypa1-security-update.com/login",
        "https://acme-bank-update-alert.net/login",
        "https://paypal.com/signin",
        "@paypa1_support",
        "https://microsoft-login-verify-account.example/",
        "com.example.paypal.assistant",
        "https://messages.example/account-alert",
    }
    by_target = {case["target"]: case for case in cases}
    assert set(by_target) == expected_targets

    # The dashboard list must expose the synthetic cases through the same
    # detail/report routes used by the frontend when a row is opened.
    for target in expected_targets:
        listed = by_target[target]
        detail_resp = client.get(f"/api/v1/cases/{listed['id']}")
        assert detail_resp.status_code == 200
        detail = detail_resp.json()
        assert detail["target"] == target
        assert detail["events"]

        report_resp = client.get(f"/api/v1/cases/{listed['id']}/report")
        assert report_resp.status_code == 200
        report = report_resp.json()
        assert report["target"] == target
        assert report["snapshot"]["provenance"]["is_synthetic"] is True

    # Synthetic candidates are triage examples, not confirmed incidents.
    paypal_case = by_target["https://paypa1-security-update.com/login"]
    assert "possible" in paypal_case["title"].lower()
    review_history = client.get("/api/v1/review/history").json()
    synthetic_review = next(
        review for review in review_history if review["target"] == paypal_case["target"]
    )
    assert synthetic_review["verdict"] == "suspicious"
    assert "no live page" in synthetic_review["reason"].lower()
    assert "was verified" in synthetic_review["reason"].lower()
    assert not any(
        review["verdict"] == "malicious"
        and review["target"] == paypal_case["target"]
        for review in review_history
    )


def test_seeder_corrects_only_the_legacy_synthetic_confirmation() -> None:
    """Upgrade the exact old demo claim without changing unrelated analyst reviews."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    target = "https://paypa1-security-update.com/login"
    old_reason = (
        "Confirmed credential harvester mimicking official PayPal login with homoglyph '1'."
    )
    correction_note = (
        "Demo-data correction: earlier seeded wording claimed a confirmed credential harvester "
        "without evidence. This is a synthetic triage example; no live page or credential theft "
        "was verified."
    )
    acme_target = "https://acme-bank-update-alert.net/login"
    acme_correction = (
        "Demo-data correction: the earlier seeded title called this a fake portal without "
        "verification. This is a synthetic URL candidate; no live page or incident was verified."
    )

    with Session(engine) as db:
        case = Case(
            title="PayPal Credential Harvester on Typosquat Domain",
            target=target,
            status=CaseStatus.IN_REVIEW,
            gate_outcome="not_matched",
            alert_eligible=True,
            snapshot=json.dumps({"provenance": SYNTHETIC_PROVENANCE}),
        )
        db.add(case)
        db.flush()
        acme_case = Case(
            title="Acme Bank Fake Account Verification Portal",
            target=acme_target,
            status=CaseStatus.OPEN,
            gate_outcome="not_matched",
            alert_eligible=True,
            snapshot=json.dumps({"provenance": SYNTHETIC_PROVENANCE}),
        )
        db.add(acme_case)
        db.flush()
        db.add_all(
            [
                HumanReview(
                    case_id=case.id,
                    target=target,
                    verdict=ReviewVerdict.MALICIOUS,
                    reason=old_reason,
                    analyst="security_analyst_1",
                    tags=json.dumps(["demo", "synthetic"]),
                    label=1,
                ),
                HumanReview(
                    case_id=case.id,
                    target=target,
                    verdict=ReviewVerdict.BENIGN,
                    reason="Separate analyst review retained for this test.",
                    analyst="reviewer",
                    tags=json.dumps(["manual"]),
                    label=0,
                ),
                CaseEvent(
                    case_id=case.id,
                    event_type="decision",
                    note=f"Human review: MALICIOUS. Reason: {old_reason}",
                    actor="security_analyst_1",
                ),
                CaseEvent(
                    case_id=acme_case.id,
                    event_type="note",
                    note="User-submitted suspicious SMS link targeting Acme Bank customers.",
                    actor="analyst",
                ),
            ]
        )
        db.commit()

        first = seed_demo_data(db)
        assert first.cases_created == 5
        refreshed_case = db.scalar(select(Case).where(Case.target == target))
        assert refreshed_case is not None
        assert refreshed_case.title == (
            "Possible PayPal-Style Impersonation — Synthetic Typosquat URL"
        )
        refreshed_acme_case = db.scalar(select(Case).where(Case.target == acme_target))
        assert refreshed_acme_case is not None
        assert refreshed_acme_case.title == "Synthetic Acme Bank-Style Phishing URL Candidate"

        reviews = list(db.scalars(select(HumanReview).where(HumanReview.case_id == case.id)))
        corrected = next(review for review in reviews if review.analyst == "security_analyst_1")
        manual = next(review for review in reviews if review.analyst == "reviewer")
        assert corrected.verdict == ReviewVerdict.SUSPICIOUS
        assert "no live page" in corrected.reason.lower()
        assert manual.verdict == ReviewVerdict.BENIGN
        assert manual.reason == "Separate analyst review retained for this test."

        events = list(db.scalars(select(CaseEvent).where(CaseEvent.case_id == case.id)))
        assert any("Human review: MALICIOUS" in event.note for event in events)
        assert sum(event.note == correction_note for event in events) == 1
        acme_events = list(
            db.scalars(select(CaseEvent).where(CaseEvent.case_id == acme_case.id))
        )
        assert sum(event.note == acme_correction for event in acme_events) == 1

        second = seed_demo_data(db)
        assert second.cases_created == 0
        events = list(db.scalars(select(CaseEvent).where(CaseEvent.case_id == case.id)))
        assert sum(event.note == correction_note for event in events) == 1
        acme_events = list(
            db.scalars(select(CaseEvent).where(CaseEvent.case_id == acme_case.id))
        )
        assert sum(event.note == acme_correction for event in acme_events) == 1

    engine.dispose()
