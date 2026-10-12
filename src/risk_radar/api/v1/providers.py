"""Safe provider configuration diagnostics; never return credential values."""

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

from risk_radar.core.config import get_settings

router = APIRouter(tags=["providers"])


class ProviderConfiguration(BaseModel):
    """Configuration presence and selected provider, without secret material."""

    selected_search_provider: Literal["brave", "tavily", "exa"]
    key_configured: dict[str, bool]


@router.get(
    "/providers/configuration",
    response_model=ProviderConfiguration,
    summary="Check which optional provider keys are configured",
)
def provider_configuration() -> ProviderConfiguration:
    """Report only key presence booleans; never expose credentials."""
    settings = get_settings()
    return ProviderConfiguration(
        selected_search_provider=settings.search_provider,
        key_configured=settings.provider_key_status,
    )
