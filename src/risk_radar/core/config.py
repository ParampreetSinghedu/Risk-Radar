"""Environment-backed application settings."""

import re
import urllib.parse
from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url


def normalize_database_url(raw: str | URL) -> URL:
    """Normalize a database connection URL for SQLAlchemy and the psycopg v3 driver.

    - Converts postgres:// and postgresql:// schemes to postgresql+psycopg://.
    - Preserves postgresql+psycopg://, sqlite://, and any other valid dialect schemes.
    - Safely percent-encodes unencoded special characters in username/password credentials.
    - Preserves Supabase pooler host, port, database, and query parameters (such as sslmode).
    """
    if isinstance(raw, URL):
        return raw

    raw_str = raw.strip()
    if not raw_str:
        raise ValueError("Database URL cannot be empty")

    match = re.match(
        r"^(postgres|postgresql|postgresql\+psycopg)://(.*)$",
        raw_str,
        re.IGNORECASE,
    )
    if match:
        rest = match.group(2)
        # Match user credentials, host (including Supabase pooler), port, db, and query
        m = re.search(r"@([a-zA-Z0-9.\-]+(?::\d+)?)(/[^?#]*)?(\?[^#]*)?$", rest)
        if m:
            host_with_port = m.group(1)
            db_path = m.group(2) or ""
            query_str = m.group(3) or ""
            userinfo = rest[: m.start()]
            if ":" in userinfo:
                user, pwd = userinfo.split(":", 1)
                user_enc = urllib.parse.quote(urllib.parse.unquote(user), safe="")
                pwd_enc = urllib.parse.quote(urllib.parse.unquote(pwd), safe="")
                userinfo_str = f"{user_enc}:{pwd_enc}@"
            elif userinfo:
                user_enc = urllib.parse.quote(urllib.parse.unquote(userinfo), safe="")
                userinfo_str = f"{user_enc}@"
            else:
                userinfo_str = ""
            raw_str = f"postgresql+psycopg://{userinfo_str}{host_with_port}{db_path}{query_str}"
        else:
            raw_str = f"postgresql+psycopg://{rest}"

    return make_url(raw_str)


class Settings(BaseSettings):
    """Runtime configuration for the API and infrastructure connections."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        populate_by_name=True,
        extra="ignore",
    )

    app_name: str = "Risk Radar API"
    app_environment: str = "local"

    # Explicit database connection URL (takes precedence over POSTGRES_* settings)
    database_url_env: str | None = Field(
        default=None,
        validation_alias=AliasChoices("database_url", "database_url_env"),
    )

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
    brave_search_api_key: SecretStr | None = None
    tavily_api_key: SecretStr | None = None
    exa_api_key: SecretStr | None = None
    search_provider: Literal["brave", "tavily", "exa"] = "brave"
    brave_search_timeout_seconds: float = 8.0
    search_provider_timeout_seconds: float = 8.0

    # LLM investigator & RAG analysis (Stages 9 & 12)
    llm_provider: str = ""
    llm_model: str = "claude-3-5-haiku-latest"
    vision_model: str = "claude-haiku-4-5-20251001"
    llm_fallback_providers: str = ""
    anthropic_api_key: SecretStr | None = None
    apinex_api_key: SecretStr | None = None
    apinex_base_url: str = "https://api.apinex.bond/v1"
    apinex_model: str = "free/deepseek-v4-flash-0731"
    groq_api_key: SecretStr | None = None
    groq_model: str = "llama-3.3-70b-versatile"
    openrouter_api_key: SecretStr | None = None
    openrouter_model: str = "deepseek/deepseek-chat"
    ollama_base_url: str = "http://localhost:11434/v1"
    ollama_model: str = "llama3"

    # Evidence network resolvers (Stage 5 optional enrichment)
    evidence_enable_live_resolvers: bool = False
    evidence_dns_timeout_seconds: float = 2.0
    evidence_rdap_timeout_seconds: float = 3.0
    evidence_rdap_bootstrap_url: str = "https://rdap.org/domain/"
    evidence_enable_redirects: bool = False
    evidence_redirect_max_hops: int = 5
    evidence_redirect_timeout_seconds: float = 3.0

    # Bounded in-process monitoring scheduler; provider checks remain opt-in.
    monitoring_scheduler_enabled: bool = False
    monitoring_scheduler_poll_seconds: float = 5.0
    monitoring_scheduler_batch_size: int = 10

    @field_validator(
        "brave_search_api_key",
        "tavily_api_key",
        "exa_api_key",
        "anthropic_api_key",
        mode="before",
    )
    @classmethod
    def blank_optional_keys_are_unconfigured(cls, value):
        """Treat empty environment placeholders as absent, without exposing values."""
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @property
    def provider_key_status(self) -> dict[str, bool]:
        """Return configuration presence only; never return secret values."""
        return {
            "BRAVE_SEARCH_API_KEY": bool(
                self.brave_search_api_key
                and self.brave_search_api_key.get_secret_value().strip()
            ),
            "TAVILY_API_KEY": bool(
                self.tavily_api_key and self.tavily_api_key.get_secret_value().strip()
            ),
            "EXA_API_KEY": bool(
                self.exa_api_key and self.exa_api_key.get_secret_value().strip()
            ),
            "ANTHROPIC_API_KEY": bool(
                self.anthropic_api_key
                and self.anthropic_api_key.get_secret_value().strip()
            ),
        }

    @property
    def database_url(self) -> URL:
        """Build SQLAlchemy URL from explicit DATABASE_URL or POSTGRES_* settings."""
        if self.database_url_env and self.database_url_env.strip():
            return normalize_database_url(self.database_url_env)
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
