"""Tests for environment-backed connection configuration."""

from risk_radar.core.config import Settings


def test_redis_url_escapes_password_characters() -> None:
    """Reserved URL characters in Redis credentials must remain valid."""
    settings = Settings(
        redis_host="redis",
        redis_port=6379,
        redis_db=2,
        redis_password="p@ss:/#?%",
    )

    assert settings.redis_url == "redis://:p%40ss%3A%2F%23%3F%25@redis:6379/2"


def test_default_database_url_uses_postgres_settings() -> None:
    """When DATABASE_URL is unset, settings fallback to local POSTGRES_* defaults."""
    settings = Settings(
        postgres_host="localhost",
        postgres_port=5432,
        postgres_db="risk_radar",
        postgres_user="risk_radar",
        postgres_password="local-only-change-me",
    )

    url = settings.database_url
    assert url.drivername == "postgresql+psycopg"
    assert url.host == "localhost"
    assert url.port == 5432
    assert url.database == "risk_radar"
    assert url.username == "risk_radar"
    assert url.password == "local-only-change-me"


def test_database_url_precedence_over_postgres_defaults() -> None:
    """DATABASE_URL must take precedence over default or explicitly set POSTGRES_* parameters."""
    settings = Settings(
        database_url="postgresql://db_user:db_pass@supabase-host.com:6543/prod_db?sslmode=require",
        postgres_host="127.0.0.1",
        postgres_port=5432,
    )

    url = settings.database_url
    assert url.host == "supabase-host.com"
    assert url.port == 6543
    assert url.database == "prod_db"
    assert url.username == "db_user"
    assert url.password == "db_pass"
    assert url.drivername == "postgresql+psycopg"
    assert url.query.get("sslmode") == "require"


def test_database_url_normalizes_postgres_and_postgresql_schemes() -> None:
    """Both postgres:// and postgresql:// must normalize to postgresql+psycopg://."""
    s1 = Settings(database_url="postgres://user:pass@host:5432/mydb")
    assert s1.database_url.drivername == "postgresql+psycopg"

    s2 = Settings(database_url="postgresql://user:pass@host:5432/mydb")
    assert s2.database_url.drivername == "postgresql+psycopg"

    s3 = Settings(database_url="postgresql+psycopg://user:pass@host:5432/mydb")
    assert s3.database_url.drivername == "postgresql+psycopg"


def test_database_url_handles_supabase_pooler_with_special_characters() -> None:
    """Supabase pooler username and special character password must be parsed correctly."""
    pooler_url = (
        "postgresql://postgres.myref123:P@ss#w0rd!%24@aws-0-us-east-1.pooler.supabase.com:6543/postgres?sslmode=require"
    )
    settings = Settings(database_url=pooler_url)
    url = settings.database_url

    assert url.drivername == "postgresql+psycopg"
    assert url.username == "postgres.myref123"
    assert url.password == "P@ss#w0rd!$"
    assert url.host == "aws-0-us-east-1.pooler.supabase.com"
    assert url.port == 6543
    assert url.database == "postgres"
    assert url.query.get("sslmode") == "require"

    # Must be compatible with Alembic render_as_string
    rendered = url.render_as_string(hide_password=False)
    assert "postgresql+psycopg://" in rendered
    assert "postgres.myref123" in rendered
    assert "aws-0-us-east-1.pooler.supabase.com:6543/postgres?sslmode=require" in rendered


def test_postgres_settings_escape_special_characters() -> None:
    """POSTGRES_PASSWORD containing special characters must be safely escaped."""
    settings = Settings(
        postgres_host="db.example.com",
        postgres_port=5432,
        postgres_db="testdb",
        postgres_user="admin",
        postgres_password="p@ss:/#?%",
    )
    url = settings.database_url
    assert url.password == "p@ss:/#?%"
    rendered = url.render_as_string(hide_password=False)
    assert "p%40ss%3A%2F%23%3F%25" in rendered


def test_sqlite_url_preserved() -> None:
    """SQLite URLs for local development or testing must remain intact."""
    settings = Settings(database_url="sqlite:///./risk_radar.db")
    url = settings.database_url
    assert url.drivername == "sqlite"
    assert url.database == "./risk_radar.db"
    assert url.render_as_string(hide_password=False) == "sqlite:///./risk_radar.db"


def test_sqlalchemy_engine_creation_with_normalized_url() -> None:
    """SQLAlchemy create_engine must accept settings.database_url without error."""
    from sqlalchemy import create_engine

    settings = Settings(database_url="sqlite:///:memory:")
    engine = create_engine(settings.database_url)
    with engine.connect() as conn:
        result = conn.exec_driver_sql("SELECT 1").scalar()
        assert result == 1
    engine.dispose()


def test_regression_render_database_url_env_resolution(monkeypatch) -> None:
    """Prevent regression: Render DATABASE_URL must not default to 127.0.0.1:5432."""
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://postgres.renderref:secretpass@aws-0-us-east-1.pooler.supabase.com:6543/postgres?sslmode=require",
    )
    settings = Settings()
    assert settings.database_url.host == "aws-0-us-east-1.pooler.supabase.com"
    assert settings.database_url.port == 6543
    assert settings.database_url.host != "localhost"
    assert settings.database_url.host != "127.0.0.1"

