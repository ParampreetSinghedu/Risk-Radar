"""Environment-backed application settings."""

from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    """Runtime configuration for the API and infrastructure connections."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "Risk Radar API"
    app_environment: str = "local"

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "risk_radar"
    postgres_user: str = "risk_radar"
    postgres_password: SecretStr = SecretStr("local-only-change-me")

    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: SecretStr = SecretStr("local-only-change-me")

    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: SecretStr = SecretStr("local-only-change-me")
    minio_bucket: str = "risk-radar"
    minio_secure: bool = False

    # Discovery feeds (Stage 3)
    urlhaus_auth_key: SecretStr | None = None

    # LLM investigator (Stage 9)
    llm_provider: str = ""
    llm_model: str = "claude-3-5-haiku-latest"
    anthropic_api_key: SecretStr | None = None

    @property
    def database_url(self) -> URL:
        """Build a safely escaped SQLAlchemy URL from PostgreSQL settings."""
        return URL.create(
            drivername="postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        )

    @property
    def redis_url(self) -> str:
        """Build a Redis URL with its password safely URL-encoded."""
        return URL.create(
            drivername="redis",
            username="",
            password=self.redis_password.get_secret_value(),
            host=self.redis_host,
            port=self.redis_port,
            database=str(self.redis_db),
        ).render_as_string(hide_password=False)


@lru_cache
def get_settings() -> Settings:
    """Return cached settings so all app modules use one configuration."""
    return Settings()
