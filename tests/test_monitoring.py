"""Monitoring persistence, repeat checks, change detection, and alert API tests."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from risk_radar.db.models import MonitoringObservation, MonitoringTarget
from risk_radar.monitoring.service import MonitorCheckResult, MonitoringService, MonitorSignal


def _session(client):
    from risk_radar.db.session import get_db

    return next(client.app.dependency_overrides[get_db]())


def _create(client, **overrides):
    body = {"target_type": "domain", "target": "brand.example", "interval_seconds": 60}
    body.update(overrides)
    return client.post("/api/v1/monitoring/targets", json=body)


class SequenceChecker:
    def __init__(self, results):
        self.results = list(results)
        self.calls = 0

    def check(self, target, db):
        self.calls += 1
        return self.results.pop(0)


def _complete(payload="203.0.113.10"):
    return MonitorCheckResult(
        status="completed",
        providers={"authorized_fixture": {"status": "completed"}},
        complete_sources=["authorized_fixture"],
        observations=[
            MonitorSignal(
                source="authorized_fixture",
                kind="profile",
                key="profile-1",
                payload={"target": "@brand_help", "metadata": {"description": payload}},
            )
        ],
    )


def test_monitor_target_validation_persistence_pause_resume_and_remove(client):
    created = _create(client, target="https://BRAND.example/path")
    assert created.status_code == 201
    body = created.json()
    assert body["target"] == "brand.example"
    assert body["last_status"] == "never_checked"
    assert body["active_monitoring"] is False
    assert body["next_check_at"]

    assert client.get(f"/api/v1/monitoring/targets/{body['id']}").json()["id"] == body["id"]
    assert (
        client.patch(f"/api/v1/monitoring/targets/{body['id']}", json={"enabled": False}).json()[
            "next_check_at"
        ]
        is None
    )
    resumed = client.patch(f"/api/v1/monitoring/targets/{body['id']}", json={"enabled": True})
    assert resumed.status_code == 200 and resumed.json()["next_check_at"]
    assert client.delete(f"/api/v1/monitoring/targets/{body['id']}").json()["removed"] is True
    assert client.get(f"/api/v1/monitoring/targets/{body['id']}").status_code == 404
    restored = _create(client, target="brand.example", interval_seconds=120)
    assert restored.status_code == 201
    assert restored.json()["id"] == body["id"]
    assert restored.json()["interval_seconds"] == 120


def test_monitor_target_rejects_bad_types_intervals_and_duplicates(client):
    assert _create(client, target="http://127.0.0.1").status_code == 422
    assert _create(client, target_type="social_profile", target="not-a-handle").status_code == 422
    assert (
        _create(client, target_type="application", target="javascript:alert(1)").status_code == 422
    )
    assert _create(client, interval_seconds=59).status_code == 422
    assert _create(client).status_code == 201
    assert _create(client, target="BRAND.EXAMPLE").status_code == 409


def test_unconfigured_social_provider_persists_unavailable_without_active_claim(client):
    target = client.post(
        "/api/v1/monitoring/targets",
        json={"target_type": "social_profile", "target": "@brand_help"},
    ).json()
    check = client.post(f"/api/v1/monitoring/targets/{target['id']}/check", json={})
    assert check.status_code == 200
    body = check.json()
    assert body["status"] == "unavailable"
    assert "authorized platform API provider" in body["error"]
    refreshed = client.get(f"/api/v1/monitoring/targets/{target['id']}").json()
    assert refreshed["last_check_at"]
    assert refreshed["last_success_at"] is None
    assert refreshed["active_monitoring"] is False
    assert client.get("/api/v1/monitoring/alerts").json() == []


def test_repeat_checks_detect_new_unchanged_changed_and_unavailable_and_acknowledge(client):
    target = _create(client).json()
    now = datetime(2026, 10, 11, tzinfo=UTC)
    checker = SequenceChecker(
        [
            _complete("old"),
            _complete("old"),
            _complete("changed"),
            MonitorCheckResult(
                status="partial",
                providers={"authorized_fixture": {"status": "unavailable"}},
                error="provider timed out",
            ),
            MonitorCheckResult(
                status="completed",
                providers={"authorized_fixture": {"status": "completed"}},
                complete_sources=["authorized_fixture"],
            ),
            MonitorCheckResult(
                status="completed",
                providers={"authorized_fixture": {"status": "completed"}},
                complete_sources=["authorized_fixture"],
            ),
        ]
    )
    service = MonitoringService(checker=checker, clock=lambda: now)
    db = _session(client)
    first = service.run_check(db, target["id"])
    second = service.run_check(db, target["id"])
    third = service.run_check(db, target["id"])
    partial = service.run_check(db, target["id"])
    disappeared = service.run_check(db, target["id"])
    repeated_empty = service.run_check(db, target["id"])
    assert [first.status, second.status, third.status, partial.status] == [
        "completed",
        "completed",
        "completed",
        "partial",
    ]

    alerts = client.get("/api/v1/monitoring/alerts").json()
    assert [item["change_type"] for item in alerts].count("new") == 1
    assert [item["change_type"] for item in alerts].count("changed") == 1
    assert [item["change_type"] for item in alerts].count("unavailable") == 1
    # The partial provider failure did not clear the old observation.
    assert any(
        item["change_type"] == "unchanged" for item in json_changes(client, target["id"], second.id)
    )
    assert any(
        item["change_type"] == "unverifiable"
        for item in json_changes(client, target["id"], partial.id)
    )
    assert disappeared.id != repeated_empty.id
    assert not db.scalars(
        select(MonitoringObservation).where(
            MonitoringObservation.target_id == target["id"], MonitoringObservation.active.is_(True)
        )
    ).all()

    alert = next(item for item in alerts if item["change_type"] == "new")
    ack = client.post(
        f"/api/v1/monitoring/alerts/{alert['id']}/acknowledge",
        json={"acknowledged_by": "analyst-7"},
    )
    assert ack.status_code == 200
    assert ack.json()["acknowledged_by"] == "analyst-7"
    assert (
        client.get("/api/v1/monitoring/alerts", params={"acknowledged": "true"}).json()[0]["id"]
        == alert["id"]
    )
    assert client.get("/api/v1/monitoring/alerts", params={"acknowledged": "false"}).json()


def json_changes(client, target_id, check_id):
    from sqlalchemy import select

    from risk_radar.db.models import MonitoringCheck

    row = _session(client).scalar(select(MonitoringCheck).where(MonitoringCheck.id == check_id))
    return json.loads(row.result_json)["changes"]


def test_scheduler_due_batch_survives_service_recreation(client):
    target = _create(client).json()
    db = _session(client)
    row = db.get(MonitoringTarget, target["id"])
    row.next_check_at = datetime(2026, 10, 10, tzinfo=UTC)
    db.commit()
    fixed_now = datetime(2026, 10, 11, tzinfo=UTC)
    first_service = MonitoringService(
        checker=SequenceChecker([_complete()]), clock=lambda: fixed_now
    )
    check_ids = first_service.run_due(db, limit=3)
    assert len(check_ids) == 1
    # A fresh service has no in-memory queue; due state and run history are in the DB.
    row = db.get(MonitoringTarget, target["id"])
    assert row.next_check_at.replace(tzinfo=UTC) == fixed_now + timedelta(seconds=60)
    second_service = MonitoringService(
        checker=SequenceChecker([_complete()]), clock=lambda: fixed_now
    )
    assert second_service.run_due(db) == []
    assert len(client.get(f"/api/v1/monitoring/targets/{target['id']}/checks").json()) == 1


def test_duplicate_concurrent_claim_is_rejected_and_pause_blocks_check(client):
    target = _create(client).json()
    db = _session(client)
    service = MonitoringService(checker=SequenceChecker([_complete()]))
    row = db.get(MonitoringTarget, target["id"])
    row.check_started_at = datetime.now(UTC)
    db.commit()
    assert service.run_check(db, target["id"]) is None
    db.refresh(row)
    row.check_started_at = None
    row.enabled = False
    db.commit()
    assert service.run_check(db, target["id"]) is None
    assert service.checker.calls == 0


def test_overlapping_check_attempt_cannot_execute_provider_twice(client):
    target = _create(client).json()
    db = _session(client)
    rejected = SequenceChecker([_complete()])
    result = _complete()

    class OverlappingChecker:
        nested_check = "not attempted"
        calls = 0

        def check(self, target_row, session):
            self.calls += 1
            self.nested_check = MonitoringService(checker=rejected).run_check(
                session, target_row.id
            )
            return result

    checker = OverlappingChecker()
    check = MonitoringService(checker=checker).run_check(db, target["id"])
    assert check is not None
    assert checker.calls == 1
    assert checker.nested_check is None
    assert rejected.calls == 0


def test_retrieval_timestamp_churn_does_not_create_duplicate_change_alert(client):
    target = _create(client).json()
    results = [
        MonitorCheckResult(
            status="completed",
            providers={"provider": {"status": "completed"}},
            complete_sources=["provider"],
            observations=[
                MonitorSignal(
                    source="provider",
                    kind="listing",
                    key="app-1",
                    payload={"app_name": "Acme", "retrieved_at": stamp},
                )
            ],
        )
        for stamp in ("2026-10-11T00:00:00+00:00", "2026-10-11T01:00:00+00:00")
    ]
    service = MonitoringService(checker=SequenceChecker(results))
    db = _session(client)
    service.run_check(db, target["id"])
    second = service.run_check(db, target["id"])
    alerts = client.get("/api/v1/monitoring/alerts").json()
    assert len(alerts) == 1
    assert json_changes(client, target["id"], second.id)[0]["change_type"] == "unchanged"


def test_check_history_api_and_ack_unknown_alert(client):
    target = _create(client).json()
    response = client.post(f"/api/v1/monitoring/targets/{target['id']}/check", json={})
    assert response.status_code == 200
    history = client.get(f"/api/v1/monitoring/targets/{target['id']}/checks")
    assert history.status_code == 200 and len(history.json()) == 1
    assert client.post("/api/v1/monitoring/alerts/999/acknowledge", json={}).status_code == 404


def test_runtime_status_reports_scheduler_and_unavailable_provider_configuration(client):
    response = client.get("/api/v1/monitoring/status")
    assert response.status_code == 200
    body = response.json()
    assert body["scheduler_enabled"] is False
    assert "no authorized platform provider" in body["providers"]["social"]
    assert "network not probed" in body["providers"]["apple_app_store"]
    assert "disabled by configuration" in body["providers"]["redirects"]


def test_reentered_application_lifespan_reuses_one_scheduler(monkeypatch):
    from risk_radar import main

    async def exercise_lifespans():
        monkeypatch.setattr(main.settings, "monitoring_scheduler_enabled", True)
        monkeypatch.setattr(main.settings, "monitoring_scheduler_poll_seconds", 300)
        monkeypatch.setattr(main, "try_claim_scheduler_batch", lambda: False)
        async with main.lifespan(main.app):
            task = main.app.state.monitoring_scheduler_task
            async with main.lifespan(main.app):
                assert main.app.state.monitoring_scheduler_task is task
                assert main.app.state.monitoring_scheduler_users == 2
            assert not task.cancelled()
        assert task.cancelled()
        assert not hasattr(main.app.state, "monitoring_scheduler_task")

    asyncio.run(exercise_lifespans())


def test_failed_check_releases_claim_and_stale_claim_is_recoverable(client):
    target = _create(client).json()

    class FailingChecker:
        def check(self, target_row, db):
            raise TimeoutError("provider timeout")

    db = _session(client)
    failed = MonitoringService(checker=FailingChecker()).run_check(db, target["id"])
    assert failed.status == "failed"
    row = db.get(MonitoringTarget, target["id"])
    assert row.check_started_at is None

    fixed_now = datetime(2026, 10, 11, tzinfo=UTC)
    row.check_started_at = fixed_now - timedelta(minutes=6)
    db.commit()
    recovered = MonitoringService(
        checker=SequenceChecker([_complete()]), clock=lambda: fixed_now
    ).run_check(db, target["id"])
    assert recovered.status == "completed"
    db.refresh(row)
    assert row.check_started_at is None


def test_scheduler_batch_slot_is_single_and_released_after_failure(monkeypatch):
    from risk_radar.monitoring import service as monitoring_service

    assert monitoring_service.try_claim_scheduler_batch() is True
    assert monitoring_service.try_claim_scheduler_batch() is False
    monkeypatch.setattr(
        monitoring_service,
        "scheduler_batch",
        lambda _limit: (_ for _ in ()).throw(RuntimeError("test batch failure")),
    )
    with pytest.raises(RuntimeError, match="test batch failure"):
        monitoring_service.run_claimed_scheduler_batch(1)
    assert monitoring_service.try_claim_scheduler_batch() is True
    monitoring_service.release_scheduler_batch_claim()
