"""Shared pytest fixtures for the test suite."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient


def pytest_configure() -> None:
    """Keep tests offline and independent of ignored developer .env settings."""
    for setting in (
        "LLM_PROVIDER",
        "LLM_FALLBACK_PROVIDERS",
        "APINEX_API_KEY",
        "ANTHROPIC_API_KEY",
        "GROQ_API_KEY",
        "OPENROUTER_API_KEY",
        "BRAVE_SEARCH_API_KEY",
        "TAVILY_API_KEY",
        "EXA_API_KEY",
        "URLHAUS_AUTH_KEY",
    ):
        os.environ[setting] = ""
    os.environ["SEARCH_PROVIDER"] = "brave"
    os.environ["EVIDENCE_ENABLE_LIVE_RESOLVERS"] = "false"
    os.environ["EVIDENCE_ENABLE_REDIRECTS"] = "false"
    os.environ["MONITORING_SCHEDULER_ENABLED"] = "false"


@pytest.fixture()
def client() -> Iterator[TestClient]:
    """Provide a TestClient backed by an isolated in-memory SQLite database."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker
    from sqlalchemy.pool import StaticPool

    from risk_radar.api.v1.investigate import get_investigator_service
    from risk_radar.db.base import Base
    from risk_radar.db.session import get_db
    from risk_radar.investigator.service import InvestigatorService
    from risk_radar.main import app

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db() -> Iterator[Session]:
        session = testing_session()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    # The normal investigator may include public feeds; keep the shared test
    # client offline unless an individual test explicitly injects connectors.
    app.dependency_overrides[get_investigator_service] = lambda: InvestigatorService(
        provider=None, connectors=[]
    )
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()
