"""SDK-agnostic LLM provider abstraction (function calling).

Entry point: `build_provider(settings)`. `agent.py` and `verifier.py` only
depend on `LLMProvider`/`CompletionResult`/`ToolCallRequest`, never directly
on the `openai` SDK or on a specific provider.
"""

from __future__ import annotations

from .factory import build_provider
from .openai_compatible import OpenAICompatibleProvider
from .provider import CompletionResult, LLMProvider, ToolCallRequest, Usage

__all__ = [
    "LLMProvider",
    "CompletionResult",
    "ToolCallRequest",
    "Usage",
    "OpenAICompatibleProvider",
    "build_provider",
]
