"""`LLMProvider` implementation for any provider exposing an OpenAI-compatible
function-calling API — this is the case for DeepSeek and Mistral (compatible
`/v1/chat/completions` endpoint), so a single client serves both: only
`base_url`, `model` and the key change.
"""

from __future__ import annotations

import json
from typing import Any

from openai import OpenAI

from .provider import CompletionResult, LLMProvider, ToolCallRequest, Usage


# Assistant message keys fed back as-is into the history
# (agent.py:messages.append(decision.message)) on the next turn. The openai
# SDK also dumps OpenAI-specific extensions (`refusal`, `annotations`,
# `audio`, `function_call`, all `None` in our usage) that DeepSeek silently
# ignores but Mistral's strict schema rejects (422 extra_forbidden — verified
# empirically). We only keep the keys of the OpenAI/Mistral-compatible chat
# message format.
_MESSAGE_DICT_ALLOWED_KEYS = {"role", "content", "tool_calls", "tool_call_id", "name"}


def _sanitize_message_dict(raw: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in raw.items() if k in _MESSAGE_DICT_ALLOWED_KEYS}


# The openai SDK already retries natively (exponential backoff + jitter,
# honoring the Retry-After header) on 429/408/409/5xx — no need to
# reimplement that logic. Its default (2) is too low for the harness: several
# domains run in parallel (ThreadPoolExecutor), each chaining several close
# LLM calls, which can burst past a per-second quota even when the per-minute
# quota is comfortable (seen with mistral-small-2603, 1.67 req/s — 2 attempts
# were not enough to absorb a burst of 4 concurrent tasks). 8 gives headroom
# without risking hiding a real quota block (zero balance, invalid key)
# behind an endless wait.
_MAX_RETRIES = 8


class OpenAICompatibleProvider(LLMProvider):
    """Generic provider driven by the `openai` SDK in compatibility mode."""

    def __init__(
        self,
        *,
        name: str,
        api_key: str,
        base_url: str,
        model: str,
        timeout: float = 30.0,
        temperature: float | None = None,
        seed: int | None = None,
    ) -> None:
        self.name = name
        self.model = model
        self.temperature = temperature
        self.seed = seed
        self._client = OpenAI(
            api_key=api_key, base_url=base_url, timeout=timeout, max_retries=_MAX_RETRIES
        )

    def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        tool_choice: Any = "auto",
    ) -> CompletionResult:
        extra: dict[str, Any] = {}
        if self.temperature is not None:
            extra["temperature"] = self.temperature
        if self.seed is not None:
            # Mistral rejects the OpenAI `seed` field (strict schema, 422
            # extra_forbidden — verified empirically); its equivalent is
            # `random_seed`, passed via extra_body since it is outside the
            # openai SDK schema. DeepSeek accepts `seed` natively.
            if self.name == "mistral":
                extra["extra_body"] = {"random_seed": self.seed}
            else:
                extra["seed"] = self.seed

        response = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=tools,
            tool_choice=tool_choice,
            **extra,
        )
        message = response.choices[0].message

        tool_calls: list[ToolCallRequest] = []
        for call in message.tool_calls or []:
            try:
                args = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(ToolCallRequest(id=call.id, name=call.function.name, arguments=args))

        usage_obj = getattr(response, "usage", None)
        usage = Usage(
            prompt_tokens=getattr(usage_obj, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage_obj, "completion_tokens", 0) or 0,
            total_tokens=getattr(usage_obj, "total_tokens", 0) or 0,
        )

        return CompletionResult(
            message=_sanitize_message_dict(message.model_dump()),
            content=message.content,
            tool_calls=tool_calls,
            usage=usage,
        )
