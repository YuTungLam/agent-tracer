"""Route MELON's backbone (AgentDojo 0.1.24 ``OpenAILLM``) to DeepSeek through the budget guard.

The artifact never builds the chat client itself: the README wiring passes an
AgentDojo LLM element into ``MELON(llm, ...)`` and MELON calls ``llm.query``
for both the original and the masked run (pi_detector.py:311, :365). So the
backbone is routed by giving AgentDojo 0.1.24's own ``OpenAILLM`` an OpenAI
client whose ``base_url`` is the loopback guard. Nothing in the artifact or in
AgentDojo is edited.

This module adds three things around that client, in this process only:

1. ``require_loopback_base_url``: the adapter refuses any base URL that is not
   loopback, so every chat request must pass the guard (which holds the real
   key, counts usage and enforces the stage caps).
2. ``shape_request``: DeepSeek wire shaping, matching the lab's DeepSeek adapter
   (``agentdojo_lab/deepseek_adapter.py``) and the lab provider config: model
   must be ``deepseek-flash``; ``max_tokens`` (never ``max_completion_tokens``);
   ``extra_body.thinking = {"type": "disabled"}``; tool messages lose the
   ``name`` field. AgentDojo 0.1.24 itself sends ``temperature=0.0``
   (openai_llm.py:105-113), which is kept.
3. ``EpisodeMeter``: a per-episode request cap and a usage tally with no prompt
   text, so a looping episode stops before it can drain the stage budget.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

DEEPSEEK_MODEL = "deepseek-flash"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
MASKED_RUN_MARKER = "random.txt"  # pi_detector.py:327 and :352: only the masked run asks for random.txt


class EpisodeCapExceeded(RuntimeError):
    """Raised before sending a request that would exceed the per-episode request cap."""


def require_loopback_base_url(base_url: str | None) -> str:
    if not base_url:
        raise ValueError("OPENAI_BASE_URL is not set; start the adapter through the guard (stage runner)")
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"guard base URL must be http(s), got {parsed.scheme!r}")
    if parsed.hostname not in LOOPBACK_HOSTS:
        raise ValueError(
            f"refusing non-loopback base URL host {parsed.hostname!r}: chat traffic must go through the local guard"
        )
    return base_url


def is_masked_run(messages: list[Any]) -> bool:
    for message in messages:
        if isinstance(message, dict) and message.get("role") == "user" and MASKED_RUN_MARKER in str(message.get("content")):
            return True
    return False


def shape_request(kwargs: dict[str, Any], *, model: str = DEEPSEEK_MODEL, max_tokens: int = 2048) -> dict[str, Any]:
    """Return a copy of the SDK kwargs with DeepSeek wire shaping applied."""
    if kwargs.get("model") != model:
        raise ValueError(f"backbone model must be {model!r}, got {kwargs.get('model')!r}")
    if "max_completion_tokens" in kwargs or "reasoning_effort" in kwargs:
        raise ValueError("max_completion_tokens / reasoning_effort are not DeepSeek fields")
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens < 1:
        raise ValueError("max_tokens must be a positive integer")
    shaped = dict(kwargs)
    messages = []
    for message in kwargs.get("messages", []):
        item = dict(message)
        if item.get("role") == "tool":
            item.pop("name", None)
        messages.append(item)
    shaped["messages"] = messages
    shaped["max_tokens"] = max_tokens
    extra_body = dict(shaped.get("extra_body") or {})
    extra_body["thinking"] = {"type": "disabled"}
    shaped["extra_body"] = extra_body
    return shaped


class EpisodeMeter:
    """Counts requests and usage for one episode; no prompt or completion text is stored."""

    def __init__(self, max_requests: int) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        self.max_requests = max_requests
        self.requests: list[dict[str, Any]] = []
        self.api_errors: list[dict[str, Any]] = []

    @property
    def request_count(self) -> int:
        return len(self.requests)

    def totals(self) -> dict[str, Any]:
        out = {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0, "requests_without_usage": 0}
        by_kind: dict[str, dict[str, int]] = {}
        for row in self.requests:
            out["requests"] += 1
            kind = by_kind.setdefault(row["kind"], {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0})
            kind["requests"] += 1
            if row.get("prompt_tokens") is None:
                out["requests_without_usage"] += 1
                continue
            for key in ("prompt_tokens", "completion_tokens"):
                out[key] += int(row.get(key) or 0)
                kind[key] += int(row.get(key) or 0)
        out["by_kind"] = by_kind
        out["api_errors"] = len(self.api_errors)
        return out


def install_route(client: Any, meter: EpisodeMeter, *, model: str = DEEPSEEK_MODEL, max_tokens: int = 2048,
                  clock: Callable[[], float] = time.monotonic) -> None:
    """Wrap ``client.chat.completions.create`` with shaping, the episode cap and the usage tally."""
    original = client.chat.completions.create

    def routed_create(**kwargs: Any) -> Any:
        if meter.request_count >= meter.max_requests:
            raise EpisodeCapExceeded(f"episode request cap {meter.max_requests} reached")
        shaped = shape_request(kwargs, model=model, max_tokens=max_tokens)
        row: dict[str, Any] = {
            "n": meter.request_count + 1,
            "kind": "masked" if is_masked_run(shaped["messages"]) else "agent",
            "n_messages": len(shaped["messages"]),
            "n_tools": len(shaped.get("tools") or []) if shaped.get("tools") is not None else 0,
            "temperature": shaped.get("temperature"),
        }
        meter.requests.append(row)
        started = clock()
        try:
            response = original(**shaped)
        except Exception as exc:  # recorded, then re-raised unchanged
            row["error"] = type(exc).__name__
            row["status_code"] = getattr(exc, "status_code", None)
            meter.api_errors.append({"n": row["n"], "type": type(exc).__name__,
                                     "status_code": getattr(exc, "status_code", None)})
            raise
        finally:
            row["seconds"] = round(clock() - started, 3)
        usage = getattr(response, "usage", None)
        row["prompt_tokens"] = getattr(usage, "prompt_tokens", None) if usage is not None else None
        row["completion_tokens"] = getattr(usage, "completion_tokens", None) if usage is not None else None
        row["response_model"] = getattr(response, "model", None)
        choices = getattr(response, "choices", None) or []
        if choices:
            message = getattr(choices[0], "message", None)
            row["finish_reason"] = getattr(choices[0], "finish_reason", None)
            row["n_tool_calls"] = len(getattr(message, "tool_calls", None) or [])
        return response

    client.chat.completions.create = routed_create
