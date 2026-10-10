"""Central configuration: LLM provider choice and API key loading.

The API key is read from the environment (.env file, never committed).
We fail early and clearly when it is missing, rather than letting the error
bubble up from the depths of the HTTP client.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

# Load .env if present (otherwise fall back to real environment variables).
load_dotenv()

DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat"
MISTRAL_BASE_URL = "https://api.mistral.ai/v1"
MISTRAL_MODEL = "mistral-large-latest"

# Kept for compatibility (legacy names used elsewhere): equivalent to the
# default provider (DeepSeek).
DEFAULT_BASE_URL = DEEPSEEK_BASE_URL
DEFAULT_MODEL = DEEPSEEK_MODEL

PROVIDERS = ("deepseek", "mistral")
DEFAULT_PROVIDER = "deepseek"


class ConfigError(RuntimeError):
    """Invalid or incomplete configuration (e.g. missing API key)."""


@dataclass(frozen=True)
class Settings:
    """Resolved agent settings."""

    provider: str = DEFAULT_PROVIDER
    api_key: str = ""
    base_url: str = DEEPSEEK_BASE_URL
    model: str = DEEPSEEK_MODEL

    # LLM-side determinism: temperature 0 by default (factual task), override
    # via OSINTLLM_TEMPERATURE; the eval path also forces a fixed seed.
    temperature: float | None = 0.0
    seed: int | None = None

    # Agent loop guardrails.
    max_iterations: int = 8
    request_timeout: float = 30.0

    # Multi-agent verification loop: max number of correction round-trips.
    max_verify_iterations: int = 2

    # Provider of the verifier agent; None = same as the main agent. Using the
    # other provider decorrelates the auditor's errors from the author's.
    verifier_provider: str | None = None


def _int_env(name: str, default: int | None) -> int | None:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _float_env(name: str, default: float | None) -> float | None:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def load_settings(provider: str | None = None) -> Settings:
    """Build settings from the environment.

    `OSINTLLM_PROVIDER` ("deepseek" | "mistral", default "deepseek") picks the
    provider; the key/URL/model variables read depend on that choice.
    Raises ConfigError if the active provider's key is missing, or if
    `OSINTLLM_PROVIDER` holds an unknown value.

    Passing `provider` forces that choice without reading `OSINTLLM_PROVIDER` —
    used by the API's one-off selector (pick a provider for one analysis or
    run without ever writing to `.env`).
    """
    provider = (provider or os.getenv("OSINTLLM_PROVIDER", DEFAULT_PROVIDER)).strip().lower()
    if provider not in PROVIDERS:
        raise ConfigError(
            f"OSINTLLM_PROVIDER={provider!r} invalid "
            f"(expected: {' | '.join(PROVIDERS)})."
        )

    if provider == "mistral":
        api_key = os.getenv("MISTRAL_API_KEY", "").strip()
        if not api_key:
            raise ConfigError(
                "MISTRAL_API_KEY is missing. "
                "Set it in .env (https://console.mistral.ai/api-keys)."
            )
        base_url = os.getenv("MISTRAL_BASE_URL", MISTRAL_BASE_URL).strip()
        model = os.getenv("MISTRAL_MODEL", MISTRAL_MODEL).strip()
    else:
        api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
        if not api_key:
            raise ConfigError(
                "DEEPSEEK_API_KEY is missing. "
                "Copy .env.example to .env and set your key "
                "(https://platform.deepseek.com/api_keys)."
            )
        base_url = os.getenv("DEEPSEEK_BASE_URL", DEEPSEEK_BASE_URL).strip()
        model = os.getenv("DEEPSEEK_MODEL", DEEPSEEK_MODEL).strip()

    verifier_provider = os.getenv("OSINTLLM_VERIFIER_PROVIDER", "").strip().lower() or None
    if verifier_provider is not None and verifier_provider not in PROVIDERS:
        raise ConfigError(
            f"OSINTLLM_VERIFIER_PROVIDER={verifier_provider!r} invalid "
            f"(expected: {' | '.join(PROVIDERS)})."
        )

    return Settings(
        provider=provider,
        api_key=api_key,
        base_url=base_url,
        model=model,
        temperature=_float_env("OSINTLLM_TEMPERATURE", 0.0),
        seed=_int_env("OSINTLLM_SEED", None),
        max_verify_iterations=_int_env("OSINTLLM_MAX_VERIFY", 2),
        request_timeout=_float_env("OSINTLLM_REQUEST_TIMEOUT", 30.0),
        verifier_provider=verifier_provider,
    )
