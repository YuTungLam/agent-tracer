"""DeepSeek wire shim for the ARGUS / AgentLure artifact.

Runs inside the artifact's own venv. Routing is by environment: ``OPENAI_BASE_URL``
points at the shared budget guard on loopback, so the artifact's own
``openai.OpenAI()`` clients (the agent and every Warrant judge) reach DeepSeek only
through the guard. This module wraps the client the artifact is handed, without
editing artifact code, and adds:

* the DeepSeek wire mapping used by ``agentdojo_lab.deepseek_adapter``: the
  ``developer`` role becomes ``system``, text-block content lists become strings,
  and the ``name`` field is dropped from tool messages;
* ``thinking`` disabled on every request (``extra_body``), and a model pin;
* per-sample accounting and a sample tag header, so a guard ledger can be joined
  to samples;
* a budget latch: once one request is refused for budget, by the guard or by the
  optional adapter-side caps, no further request leaves the process, and the
  refusal is raised as a ``BadRequestError`` so neither agentdojo's tenacity retry
  nor Warrant's ``Judge`` retries it;
* a request log with ids, wire facts and usage only. It holds no prompt or
  completion text, no headers and no key.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import httpx
import openai

try:  # openai>=1.40 ships both sentinels; Omit appeared later
    from openai._types import NotGiven, Omit

    _SENTINELS: tuple[type, ...] = (NotGiven, Omit)
except ImportError:  # pragma: no cover
    from openai._types import NotGiven

    _SENTINELS = (NotGiven,)

DEEPSEEK_MODEL = "deepseek-flash"
SAMPLE_HEADER = "X-Auditor-Sample"
STAGE_HEADER = "X-Auditor-Stage"
THINKING_DISABLED = {"type": "disabled"}
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
WIRE_VERSION = "argus-deepseek-wire/1"

# A guard refusal is recognised by HTTP 402 (also DeepSeek's "insufficient balance")
# or by this pattern in the error text. Interface assumption for the common guard.
_BUDGET_PATTERN = re.compile(r"budget|cap[ _-]?(?:reached|exceeded|exhausted)|stage[ _-]cap", re.IGNORECASE)


class BudgetRefused(openai.BadRequestError):
    """A request that was not sent, or was refused, for budget reasons."""


def budget_refused(reason: str) -> BudgetRefused:
    # A placeholder request object only; nothing is sent to this URL.
    request = httpx.Request("POST", "http://auditor-adapter.invalid/budget")
    response = httpx.Response(400, request=request)
    return BudgetRefused(f"auditor adapter: request not sent ({reason})", response=response, body=None)


def is_budget_refusal(exc: BaseException) -> bool:
    if isinstance(exc, BudgetRefused):
        return True
    if not isinstance(exc, openai.APIStatusError):
        return False
    if exc.status_code == 402:
        return True
    return bool(_BUDGET_PATTERN.search(str(exc)))


def require_loopback_base_url(environ: Mapping[str, str]) -> str:
    """Paid runs must go through the local guard: OPENAI_BASE_URL has to be a loopback URL."""
    url = environ.get("OPENAI_BASE_URL", "")
    if not url:
        raise SystemExit("OPENAI_BASE_URL is not set. Start this adapter through the stage runner, "
                         "which points it at the local budget guard.")
    host = urlsplit(url).hostname
    if host not in LOOPBACK_HOSTS:
        raise SystemExit(f"OPENAI_BASE_URL must point at the local budget guard on loopback, not host {host!r}. "
                         "Direct provider URLs are refused so that every paid request is metered and capped.")
    return url


def _given(value: Any) -> bool:
    return value is not None and not isinstance(value, _SENTINELS)


@dataclass(frozen=True)
class WirePolicy:
    """What the shim enforces on every request."""

    model: str = DEEPSEEK_MODEL
    inject_thinking_disabled: bool = True
    # None keeps the artifact's request: agentdojo 0.1.35 sends ``temperature or NOT_GIVEN``,
    # so the agent's default 0.0 is dropped and the provider default applies.
    agent_temperature: float | None = None
    # Adapter-side caps: a second layer under the guard's stage caps (and the only one
    # in a direct Ollama dry run).
    max_requests: int | None = None
    max_total_tokens: int | None = None
    stage: str = ""

    def identity(self) -> dict[str, Any]:
        """The fields that change what is sent (caps and stage label do not)."""
        return {"wire": WIRE_VERSION, "model": self.model, "thinking_disabled": self.inject_thinking_disabled,
                "agent_temperature": self.agent_temperature}


@dataclass
class SampleContext:
    """Per-sample accounting, filled by every request made for that sample."""

    sample_id: str
    row: str
    requests: int = 0
    agent_requests: int = 0
    judge_requests: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    refused: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            return {"sample_id": self.sample_id, "row": self.row, "requests": self.requests,
                    "agent_requests": self.agent_requests, "judge_requests": self.judge_requests,
                    "prompt_tokens": self.prompt_tokens, "completion_tokens": self.completion_tokens,
                    "refused": self.refused, "errors": [dict(e) for e in self.errors]}


class WireSession:
    """Run-wide state: the budget latch, totals, and the request log."""

    def __init__(self, policy: WirePolicy, log_path: Path | None = None) -> None:
        self.policy = policy
        self.log_path = log_path
        self._lock = threading.Lock()
        self.latch_reason: str | None = None
        self.requests = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.refused = 0
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def latched(self) -> bool:
        return self.latch_reason is not None

    def latch(self, reason: str) -> None:
        """Called on a refusal from upstream (the guard); counts it and stops all further requests."""
        with self._lock:
            self.refused += 1
            if self.latch_reason is None:
                self.latch_reason = reason

    def reserve(self) -> None:
        """Count one outgoing request, or raise BudgetRefused without sending it."""
        p = self.policy
        with self._lock:
            if self.latch_reason is None:
                if p.max_requests is not None and self.requests >= p.max_requests:
                    self.latch_reason = f"adapter request cap {p.max_requests} reached"
                elif p.max_total_tokens is not None and self.prompt_tokens + self.completion_tokens >= p.max_total_tokens:
                    self.latch_reason = f"adapter token cap {p.max_total_tokens} reached"
            if self.latch_reason is not None:
                self.refused += 1
                raise budget_refused(self.latch_reason)
            self.requests += 1

    def account(self, prompt: int, completion: int) -> None:
        with self._lock:
            self.prompt_tokens += prompt
            self.completion_tokens += completion

    def log(self, entry: dict[str, Any]) -> None:
        if self.log_path is None:
            return
        line = json.dumps(entry, sort_keys=True)
        with self._lock, self.log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def totals(self) -> dict[str, Any]:
        with self._lock:
            return {"requests": self.requests, "prompt_tokens": self.prompt_tokens,
                    "completion_tokens": self.completion_tokens, "refused": self.refused,
                    "latch_reason": self.latch_reason}


def _normalise_message(message: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(message)
    if out.get("role") == "developer":
        out["role"] = "system"
    if out.get("role") == "tool":
        out.pop("name", None)
    content = out.get("content")
    if isinstance(content, list):
        texts = []
        for part in content:
            if not isinstance(part, Mapping) or part.get("type") != "text":
                raise ValueError("DeepSeek wire shim: only text content parts are supported")
            texts.append(part.get("text") or "")
        out["content"] = "\n".join(texts)
    return out


def prepare_request(kwargs: Mapping[str, Any], policy: WirePolicy, sample: SampleContext) -> dict[str, Any]:
    """The request actually sent: model pinned, wire normalised, thinking disabled, sample tagged."""
    request = {k: v for k, v in kwargs.items() if _given(v)}
    model = request.get("model")
    if model != policy.model:
        raise ValueError(f"DeepSeek wire shim: model {model!r} is not the pinned model {policy.model!r}")
    if "reasoning_effort" in request:
        raise ValueError("DeepSeek wire shim: reasoning_effort is not supported")
    if "max_completion_tokens" in request:  # DeepSeek takes max_tokens
        value = request.pop("max_completion_tokens")
        request.setdefault("max_tokens", value)
    request["messages"] = [_normalise_message(m) for m in request.get("messages", [])]
    if policy.inject_thinking_disabled:
        extra_body = dict(request.get("extra_body") or {})
        if extra_body.get("thinking", THINKING_DISABLED) != THINKING_DISABLED:
            raise ValueError("DeepSeek wire shim: thinking must stay disabled")
        extra_body["thinking"] = dict(THINKING_DISABLED)
        request["extra_body"] = extra_body
    if "tools" in request and policy.agent_temperature is not None:
        request["temperature"] = policy.agent_temperature
    headers = dict(request.get("extra_headers") or {})
    headers[SAMPLE_HEADER] = sample.sample_id
    if policy.stage:
        headers[STAGE_HEADER] = policy.stage
    request["extra_headers"] = headers
    return request


def _wire_facts(request: Mapping[str, Any]) -> dict[str, Any]:
    """Shape of the request for the log; never any message text."""
    response_format = request.get("response_format")
    return {
        "kind": "agent" if "tools" in request else "judge",
        "model": request.get("model"),
        "n_messages": len(request.get("messages", [])),
        "roles": sorted({m.get("role", "?") for m in request.get("messages", [])}),
        "list_content": any(isinstance(m.get("content"), list) for m in request.get("messages", [])),
        "tool_name_field": any(m.get("role") == "tool" and "name" in m for m in request.get("messages", [])),
        "n_tools": len(request.get("tools") or []),
        "response_format": response_format.get("type") if isinstance(response_format, Mapping) else None,
        "temperature": request.get("temperature", "omitted"),
        "max_tokens": request.get("max_tokens", "omitted"),
        "thinking": (request.get("extra_body") or {}).get("thinking"),
    }


class _Completions:
    def __init__(self, owner: DeepSeekWireClient) -> None:
        self._owner = owner

    def create(self, *args: Any, **kwargs: Any) -> Any:
        if args:
            raise TypeError("DeepSeek wire shim: pass request fields as keyword arguments")
        owner = self._owner
        session, sample = owner._session, owner._sample
        request = prepare_request(kwargs, session.policy, sample)
        facts = _wire_facts(request)
        base = {"ts": round(time.time(), 3), "sample": sample.sample_id, "row": sample.row,
                "stage": session.policy.stage, **facts}
        try:
            session.reserve()
        except BudgetRefused:
            with sample._lock:
                sample.refused += 1
            session.log({**base, "status": "refused_local"})
            raise
        with sample._lock:
            sample.requests += 1
            if facts["kind"] == "agent":
                sample.agent_requests += 1
            else:
                sample.judge_requests += 1
        start = time.monotonic()
        try:
            response = owner._inner.chat.completions.create(**request)
        except Exception as exc:
            seconds = round(time.monotonic() - start, 3)
            status = getattr(exc, "status_code", None)
            if is_budget_refusal(exc):
                session.latch(f"refused upstream with status {status}")
                with sample._lock:
                    sample.refused += 1
                session.log({**base, "status": "refused_upstream", "http_status": status, "seconds": seconds})
                raise budget_refused(f"guard refused, status {status}") from None
            with sample._lock:
                sample.errors.append({"type": type(exc).__name__, "http_status": status})
            session.log({**base, "status": "error", "error_type": type(exc).__name__, "http_status": status,
                         "seconds": seconds})
            raise
        usage = getattr(response, "usage", None)
        prompt = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion = int(getattr(usage, "completion_tokens", 0) or 0)
        session.account(prompt, completion)
        with sample._lock:
            sample.prompt_tokens += prompt
            sample.completion_tokens += completion
        choices = getattr(response, "choices", None) or []
        session.log({**base, "status": "ok", "seconds": round(time.monotonic() - start, 3),
                     "prompt_tokens": prompt, "completion_tokens": completion, "usage_missing": usage is None,
                     "finish_reason": getattr(choices[0], "finish_reason", None) if choices else None,
                     "response_id": getattr(response, "id", None)})
        return response


class DeepSeekWireClient:
    """Stands in for the ``openai.OpenAI``-like client handed to the artifact.

    Only ``chat.completions.create`` is intercepted; any other attribute is delegated.
    """

    def __init__(self, inner: Any, session: WireSession, sample: SampleContext) -> None:
        self._inner = inner
        self._session = session
        self._sample = sample
        self.chat = SimpleNamespace(completions=_Completions(self))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)
