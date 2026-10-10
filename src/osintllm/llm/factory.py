"""Factory: builds the `LLMProvider` matching `Settings.provider`."""

from __future__ import annotations

from ..config import Settings
from .openai_compatible import OpenAICompatibleProvider
from .provider import LLMProvider


def build_provider(settings: Settings) -> LLMProvider:
    """DeepSeek and Mistral share the same implementation (OpenAI-compatible
    API); only `base_url`/`model`/`api_key` differ, already resolved into
    `Settings` by `load_settings()` according to `settings.provider`."""
    return OpenAICompatibleProvider(
        name=settings.provider,
        api_key=settings.api_key,
        base_url=settings.base_url,
        model=settings.model,
        timeout=settings.request_timeout,
        temperature=settings.temperature,
        seed=settings.seed,
    )
