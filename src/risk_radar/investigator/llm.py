"""LLM provider abstraction; APInex, Claude, OpenAI-compatible, and fallback support (Stage 9)."""

from typing import Protocol

import httpx

from risk_radar.core.config import Settings

_ANTHROPIC_VERSION = "2023-06-01"
_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"


class ProviderError(RuntimeError):
    """The LLM provider could not produce a usable response."""

    def __init__(self, message: str, is_permanent: bool = False) -> None:
        super().__init__(message)
        self.is_permanent = is_permanent


class LLMProvider(Protocol):
    """Minimal provider interface used by the investigator and RAG services."""

    name: str

    def complete(self, system: str, user: str) -> str:
        """Return the provider's text response for one investigation prompt."""


class OpenAICompatibleProvider:
    """Generic OpenAI-compatible Chat Completions API client (APInex, Groq, OpenRouter, Ollama)."""

    def __init__(
        self,
        name: str,
        base_url: str,
        api_key: str | None,
        model: str,
        client: httpx.Client | None = None,
        timeout: float = 25.0,
        max_tokens: int = 1024,
    ) -> None:
        self.name = name
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._client = client
        self._timeout = timeout
        self._max_tokens = max_tokens

    def complete(self, system: str, user: str) -> str:
        """Call the Chat Completions endpoint once and return text content."""
        endpoint = f"{self._base_url}/chat/completions"
        payload = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.1,
        }
        headers = {
            "content-type": "application/json",
        }
        if self._api_key:
            headers["authorization"] = f"Bearer {self._api_key}"

        try:
            if self._client is not None:
                response = self._client.post(endpoint, json=payload, headers=headers)
            else:
                with httpx.Client(timeout=self._timeout) as client:
                    response = client.post(endpoint, json=payload, headers=headers)

            if response.status_code in {401, 403}:
                raise ProviderError(
                    f"{self.name} authentication failed (status {response.status_code})",
                    is_permanent=True,
                )
            if response.status_code == 429:
                raise ProviderError(
                    f"{self.name} rate limit or quota exceeded (status 429)",
                    is_permanent=False,
                )
            if response.status_code >= 500:
                raise ProviderError(
                    f"{self.name} server error (status {response.status_code})",
                    is_permanent=False,
                )
            response.raise_for_status()
            body = response.json()
        except httpx.TimeoutException as exc:
            raise ProviderError(f"{self.name} request timed out", is_permanent=False) from exc
        except httpx.ConnectError as exc:
            raise ProviderError(
                f"{self.name} connection failed ({exc.__class__.__name__})",
                is_permanent=False,
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(
                f"{self.name} HTTP error ({exc.__class__.__name__})",
                is_permanent=False,
            ) from exc
        except ValueError as exc:
            raise ProviderError(
                f"{self.name} response was not valid JSON",
                is_permanent=False,
            ) from exc

        choices = body.get("choices") or []
        if not choices or not isinstance(choices, list):
            raise ProviderError(f"{self.name} returned no choices in response")

        message = choices[0].get("message") or {}
        content = message.get("content") or ""
        text = content.strip()
        if not text:
            raise ProviderError(f"{self.name} returned an empty response")
        return text


class ClaudeProvider:
    """Anthropic Claude Messages API client."""

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

            if response.status_code in {401, 403}:
                raise ProviderError(
                    f"claude authentication failed (status {response.status_code})",
                    is_permanent=True,
                )
            if response.status_code == 429:
                raise ProviderError(
                    "claude rate limit or quota exceeded (status 429)",
                    is_permanent=False,
                )
            if response.status_code >= 500:
                raise ProviderError(
                    f"claude server error (status {response.status_code})",
                    is_permanent=False,
                )
            response.raise_for_status()
            body = response.json()
        except httpx.TimeoutException as exc:
            raise ProviderError("claude request timed out", is_permanent=False) from exc
        except httpx.ConnectError as exc:
            raise ProviderError(
                f"claude connection failed ({exc.__class__.__name__})",
                is_permanent=False,
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(
                f"claude request failed ({exc.__class__.__name__})",
                is_permanent=False,
            ) from exc
        except ValueError as exc:
            raise ProviderError("claude response was not valid JSON", is_permanent=False) from exc

        content = body.get("content") or []
        texts = [block.get("text", "") for block in content if isinstance(block, dict)]
        text = "".join(texts).strip()
        if not text:
            raise ProviderError("claude returned an empty response")
        return text


class FallbackProvider:
    """Chains multiple configured providers in order; records which provider succeeded."""

    def __init__(self, providers: list[LLMProvider]) -> None:
        if not providers:
            raise ValueError("FallbackProvider requires at least one provider")
        self._providers = providers
        self.active_provider_name: str = providers[0].name

    @property
    def name(self) -> str:
        return self.active_provider_name

    def complete(self, system: str, user: str) -> str:
        """Try each configured provider in order until one succeeds or all fail."""
        errors: list[str] = []
        for provider in self._providers:
            self.active_provider_name = provider.name
            try:
                result = provider.complete(system=system, user=user)
                return result
            except ProviderError as exc:
                errors.append(f"{provider.name}: {exc}")
                # Permanent credential errors should not prevent trying another provider
                continue
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{provider.name}: unexpected error ({exc.__class__.__name__})")
                continue

        raise ProviderError(f"all providers failed: {'; '.join(errors)}")


def _build_single_provider(name: str, settings: Settings) -> LLMProvider | None:
    """Build a provider instance by name if valid credentials and settings exist."""
    name_clean = name.strip().lower()
    if name_clean == "apinex":
        if settings.apinex_api_key is not None:
            return OpenAICompatibleProvider(
                name="apinex",
                base_url=settings.apinex_base_url,
                api_key=settings.apinex_api_key.get_secret_value(),
                model=settings.apinex_model,
            )
        return None

    if name_clean == "claude":
        if settings.anthropic_api_key is not None:
            return ClaudeProvider(
                api_key=settings.anthropic_api_key.get_secret_value(),
                model=settings.llm_model,
            )
        return None

    if name_clean == "groq":
        if settings.groq_api_key is not None:
            return OpenAICompatibleProvider(
                name="groq",
                base_url="https://api.groq.com/openai/v1",
                api_key=settings.groq_api_key.get_secret_value(),
                model=settings.groq_model,
            )
        return None

    if name_clean == "openrouter":
        if settings.openrouter_api_key is not None:
            return OpenAICompatibleProvider(
                name="openrouter",
                base_url="https://openrouter.ai/api/v1",
                api_key=settings.openrouter_api_key.get_secret_value(),
                model=settings.openrouter_model,
            )
        return None

    if name_clean == "ollama":
        return OpenAICompatibleProvider(
            name="ollama",
            base_url=settings.ollama_base_url,
            api_key=None,
            model=settings.ollama_model,
        )

    return None


def get_provider(settings: Settings) -> LLMProvider | None:
    """Build the primary provider and any configured valid fallback providers."""
    providers: list[LLMProvider] = []

    primary_name = (settings.llm_provider or "").strip()
    if primary_name:
        primary = _build_single_provider(primary_name, settings)
        if primary is not None:
            providers.append(primary)

    # Configured fallback providers (e.g. LLM_FALLBACK_PROVIDERS="claude,groq")
    if settings.llm_fallback_providers:
        for fb_name in settings.llm_fallback_providers.split(","):
            fb_name_clean = fb_name.strip()
            if not fb_name_clean or fb_name_clean.lower() == primary_name.lower():
                continue
            fallback = _build_single_provider(fb_name_clean, settings)
            if fallback is not None:
                providers.append(fallback)

    if not providers:
        return None
    if len(providers) == 1:
        return providers[0]
    return FallbackProvider(providers)
