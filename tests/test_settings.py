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
