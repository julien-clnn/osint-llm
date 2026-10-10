"""`LLMProvider` interface — hides the provider behind an SDK-agnostic
function-calling completion call.

Goal: `OsintAgent` and `VerifierAgent` never handle a type specific to a
given SDK (e.g. the pydantic objects of the `openai` client). They only know
`CompletionResult` / `ToolCallRequest`, so any provider (DeepSeek, Mistral, a
replay provider for tests...) can be plugged in without touching the agent
loop.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCallRequest:
    """A tool call decided by the model, arguments already parsed."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Usage:
    """Token usage of a completion call (0 when not provided)."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass
class CompletionResult:
    """SDK-agnostic normalized response of a completion call.

    `message` is the assistant message as it must be fed back into the
    conversation history for the next turn (standard function-calling
    format: role, content, tool_calls with JSON-string arguments) — it is the
    ONLY part still coupled to the API format, by necessity (the history must
    stay faithful to what the model received).
    """

    message: dict[str, Any]
    content: str | None
    tool_calls: list[ToolCallRequest] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)


class LLMProvider(ABC):
    """An LLM provider supporting function calling."""

    name: str

    @abstractmethod
    def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        tool_choice: Any = "auto",
    ) -> CompletionResult:
        """One completion turn. Makes no assumption about the caller: no tool
        dispatch, no side effect — only the model's decision, normalized."""
        raise NotImplementedError
