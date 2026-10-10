"""LLM provider abstraction; Claude when configured, explicit absence when not (Stage 9)."""

from typing import Protocol

import httpx

from risk_radar.core.config import Settings

_ANTHROPIC_VERSION = "2023-06-01"
_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"


class ProviderError(RuntimeError):
    """The LLM provider could not produce a usable response."""


class LLMProvider(Protocol):
    """Minimal provider interface used by the investigator service."""

    name: str

    def complete(self, system: str, user: str) -> str:
        """Return the provider's text response for one investigation prompt."""


class ClaudeProvider:
    """Anthropic Claude Messages API client; never exercised in tests."""

    name = "claude"

    def __init__(
        self,
        api_key: str,
        model: str,
        client: httpx.Client | None = None,
        timeout: float = 20.0,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._client = client
        self._timeout = timeout

    def complete(self, system: str, user: str) -> str:
        """Call the Claude Messages API once and return its text output."""
        payload = {
            "model": self._model,
            "max_tokens": 1024,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        try:
            if self._client is not None:
                response = self._client.post(_ANTHROPIC_URL, json=payload, headers=headers)
            else:
                with httpx.Client(timeout=self._timeout) as client:
                    response = client.post(_ANTHROPIC_URL, json=payload, headers=headers)
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPError as exc:
            raise ProviderError(f"claude request failed ({exc.__class__.__name__})") from exc
        except ValueError as exc:
            raise ProviderError("claude response was not valid JSON") from exc

        content = body.get("content") or []
        texts = [block.get("text", "") for block in content if isinstance(block, dict)]
        text = "".join(texts).strip()
        if not text:
            raise ProviderError("claude returned an empty response")
        return text


def get_provider(settings: Settings) -> LLMProvider | None:
    """Build the configured provider, or None when credentials are absent."""
    if settings.llm_provider == "claude" and settings.anthropic_api_key is not None:
        return ClaudeProvider(
            api_key=settings.anthropic_api_key.get_secret_value(),
            model=settings.llm_model,
        )
    return None
