"""Provider-aware route (DeepSeek, OpenAI), budget guard and stage runner shared by the auditor adapters.

Standard library only (Python >= 3.10), so the same file runs inside every
third-party artifact's own venv.

Providers.  A stage declares exactly one provider.  Stages under ``"stages"``
are DeepSeek (as before); stages under ``"provider_stages"`` must name a
non-DeepSeek ``"provider"``.  DeepSeek behaviour is unchanged from fe2e3e0 and keeps its
constants in this file.  ``openai`` stages are described by
``common/providers.json``: the guard never rewrites the model, accepts only the
stage's exact model ids (each must carry a price in the table), adds no
``thinking`` field, clamps ``max_tokens``/``max_completion_tokens`` without
renaming them, passes ``logprobs``/``top_logprobs`` through, forwards
``/v1/embeddings`` and charges both endpoints against the stage caps.

The DeepSeek parts are:

1. ``load_deepseek_env(lab_env_path)`` reads only the ``DEEPSEEK_API_KEY`` line
   of the lab ``.env`` and returns a child-process environment from which every
   other paid-provider credential has been removed.
2. ``BudgetGuard`` is an OpenAI-compatible proxy bound to 127.0.0.1.  It holds
   the real key, forces ``model=deepseek-flash`` and disabled thinking, counts
   provider-reported usage, appends one JSON line per request to a ledger (ids
   and usage only, never prompt or completion text) and refuses requests once
   the stage token, USD or request cap is reached.  ``--dry-run-ollama``
   forwards the same requests to a local Ollama model instead.
3. ``run-stage`` starts the guard, runs one adapter command from a fresh
   scratch cwd that has no ``.env`` on its ancestor path, points the child at
   the guard with a per-run token (the child never sees the DeepSeek key), and
   writes a run receipt.  While the child runs, a ``common/.run-stage-*.lock``
   file marks the tree as in use; the receipt compares code hashes taken before
   the child started with hashes taken after it ended
   (``code.code_changed_during_run``).  Runner options after ``--`` are refused.

Wire normalisation follows the lab adapter
``packages/agentdojo-lab/src/agentdojo_lab/deepseek_adapter.py`` (developer role
to system, tool-message ``name`` dropped, text blocks joined, thinking disabled,
``max_tokens`` rather than ``max_completion_tokens``) and the wire assertion in
``packages/agentdojo-lab/configs/cross_model_pilot_v2.json`` ``providers``.

Saved tool and model output is untrusted data; this module never interprets it.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import platform
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

SCHEMA_LEDGER = "auditor-guard-ledger/v1"
SCHEMA_RECEIPT = "auditor-stage-receipt/v1"
SCHEMA_STAGES = "auditor-adapter-stages/v1"
# Non-DeepSeek stages live in a separate top-level section of the stage file.
# A runner older than this file only reads "stages", so it cannot find them and
# can never run an OpenAI stage as a DeepSeek one.
PROVIDER_STAGES_SECTION = "provider_stages"
SCHEMA_PROVIDERS = "auditor-providers/v1"

DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-flash"
DEEPSEEK_KEY_ENV = "DEEPSEEK_API_KEY"
THINKING_DISABLED = {"type": "disabled"}

OPENAI_BASE_URL = "https://api.openai.com/v1"
OPENAI_KEY_ENV = "OPENAI_API_KEY"
PAID_PROVIDERS: tuple[str, ...] = ("deepseek", "openai")
# Fields an OpenAI stage may not send: DeepSeek-only, or billed outside the
# Standard text-token prices in providers.json.
OPENAI_REFUSED_FIELDS: tuple[str, ...] = ("thinking", "audio", "web_search_options", "prediction")
# Message content parts the pre-flight estimate can price (text only); others are refused.
OPENAI_TEXT_PART_TYPES: tuple[str, ...] = ("text", "refusal")
OPENAI_TOP_LOGPROBS_MAX = 20

OLLAMA_DEFAULT_URL = "http://localhost:11434/v1"
OLLAMA_DEFAULT_MODEL = "qwen2.5:7b-instruct"
DRY_RUN_DEFAULT_CAP_REQUESTS = 10  # local plumbing runs stay small unless a stage says otherwise

COMMON_DIR = Path(__file__).resolve().parent
ADAPTERS_DIR = COMMON_DIR.parent
PROVIDERS_PATH = COMMON_DIR / "providers.json"

# Lab price snapshot, copied with its provenance.  It is not re-verified here.
PRICE_SNAPSHOT: dict[str, str] = {
    "snapshot_id": "deepseek-2026-09-30-conservative-peak-uncached",
    "model": DEEPSEEK_MODEL,
    "currency": "USD",
    "input_per_million": "0.30",
    "output_per_million": "1.20",
    "basis": "conservative peak uncached input and peak output prices; cache hits are charged as misses",
    "snapshot_date": "2026-09-30",
    "source": "packages/agentdojo-lab/scripts/run_cross_model_technical_pilot_v2.py:74-99 (PRICING_SNAPSHOTS)",
    "source_url": "https://api-docs.deepseek.com/quick_start/pricing/",
    "verification": "UNVERIFIED on 2026-10-08",
}

# Credentials of other providers are removed from every child environment.
STRIPPED_PREFIXES: tuple[str, ...] = (
    "OPENAI_", "ANTHROPIC_", "GOOGLE_", "TOGETHER_", "HF_",
    "HUGGING_FACE_", "HUGGINGFACE_", "GROQ_", "GEMINI_", "COHERE_", "CO_API_",
    "MISTRAL_", "AZURE_OPENAI_", "VERTEX", "GCP_", "GCLOUD_", "CLOUDSDK_", "AWS_",
    "DEEPSEEK_", "XAI_", "FIREWORKS_", "OPENROUTER_", "PERPLEXITY_", "REPLICATE_",
    "LANGCHAIN_", "LANGSMITH_", "WANDB_",
)
STRIPPED_SUFFIXES: tuple[str, ...] = (
    "_API_KEY", "_API_TOKEN", "_ACCESS_TOKEN", "_AUTH_TOKEN", "_SECRET",
    "_SECRET_KEY", "_TOKEN",
)
# Request fields that DeepSeek does not take or that the lab wire contract forbids.
DROPPED_FIELDS: tuple[str, ...] = (
    "reasoning_effort", "reasoning", "store", "metadata", "service_tier",
    "prediction", "modalities", "audio", "web_search_options", "parallel_tool_calls",
)
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
MAX_BODY_BYTES = 16 * 1024 * 1024
_PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*)\}")
_KEY_LINE = re.compile(rb"^\s*(?:export\s+)?DEEPSEEK_API_KEY\s*=(.*)$")
_KEY_VALUE = re.compile(r"^[!-~]{8,512}$")


class RouteError(RuntimeError):
    """Configuration or safety refusal.  Messages never contain secrets."""


# ---------------------------------------------------------------------------
# 1. Environment
# ---------------------------------------------------------------------------


def _parse_env_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    hash_at = value.find(" #")
    if hash_at >= 0:
        value = value[:hash_at]
    return value.strip()


def read_provider_key(lab_env_path: str | os.PathLike[str], key_env: str) -> str:
    """Return the value of the ``key_env`` line.  No other line of the file is decoded."""
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*_API_KEY", key_env):
        raise RouteError(f"refusing to read {key_env!r}: provider key names must end in _API_KEY")
    key_line = _KEY_LINE if key_env == DEEPSEEK_KEY_ENV else re.compile(
        rb"^\s*(?:export\s+)?" + re.escape(key_env.encode("ascii")) + rb"\s*=(.*)$")
    path = Path(lab_env_path)
    if not path.is_file():
        raise RouteError(f"lab env file not found: {path}")
    matches: list[bytes] = []
    with path.open("rb") as handle:
        for raw_line in handle:
            match = key_line.match(raw_line.rstrip(b"\r\n"))
            if match:
                matches.append(match.group(1))
    if not matches:
        raise RouteError(f"{key_env} is not set in {path}; add it before a paid stage")
    if len(matches) > 1:
        raise RouteError(f"{key_env} is defined {len(matches)} times in {path}")
    try:
        value = _parse_env_value(matches[0].decode("utf-8-sig"))
    except UnicodeDecodeError:
        raise RouteError(f"{key_env} line in {path} is not UTF-8") from None
    if not _KEY_VALUE.fullmatch(value):
        raise RouteError(f"{key_env} in {path} is empty or malformed (value not shown)")
    return value


def read_deepseek_key(lab_env_path: str | os.PathLike[str]) -> str:
    """Return the DEEPSEEK_API_KEY value.  No other line of the file is decoded."""
    return read_provider_key(lab_env_path, DEEPSEEK_KEY_ENV)


def _is_stripped(name: str) -> bool:
    upper = name.upper()
    return upper.startswith(STRIPPED_PREFIXES) or upper.endswith(STRIPPED_SUFFIXES)


def sanitized_env(base_env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Copy ``base_env`` (default ``os.environ``) without provider credentials."""
    source = os.environ if base_env is None else base_env
    return {name: value for name, value in source.items() if not _is_stripped(name)}


def stripped_names(base_env: Mapping[str, str] | None = None) -> list[str]:
    source = os.environ if base_env is None else base_env
    return sorted(name for name in source if _is_stripped(name))


def load_deepseek_env(
    lab_env_path: str | os.PathLike[str], base_env: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Child env for direct DeepSeek use: credentials stripped, OpenAI vars set.

    The returned dict carries the key in ``OPENAI_API_KEY``; never print or log
    it.  ``run-stage`` does not hand this env to the artifact: it keeps the key
    inside the guard and gives the child ``guarded_child_env`` instead.
    """
    env = sanitized_env(base_env)
    env["OPENAI_BASE_URL"] = DEEPSEEK_BASE_URL
    env["OPENAI_API_KEY"] = read_deepseek_key(lab_env_path)
    return env


def guarded_child_env(
    base_env: Mapping[str, str], guard_base_url: str, guard_token: str
) -> dict[str, str]:
    """Child env that can reach a model only through the local guard."""
    env = sanitized_env(base_env)
    no_proxy = "127.0.0.1,localhost,::1"
    env.update(
        {
            "OPENAI_BASE_URL": guard_base_url,
            "OPENAI_API_BASE": guard_base_url,
            "OPENAI_API_KEY": guard_token,
            "AUDITOR_GUARD_URL": guard_base_url,
            "AUDITOR_GUARD_TOKEN": guard_token,
            "NO_PROXY": no_proxy,
            "no_proxy": no_proxy,
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return env


def require_guard(env: Mapping[str, str] | None = None) -> tuple[str, str]:
    """For adapter scripts: return (base_url, token) or refuse to run unguarded."""
    source = os.environ if env is None else env
    base_url = source.get("AUDITOR_GUARD_URL") or ""
    token = source.get("AUDITOR_GUARD_TOKEN") or ""
    if not base_url or not token or not _is_loopback(base_url):
        raise RouteError("not running under the auditor guard; launch through deepseek_route.py run-stage")
    if source.get("OPENAI_BASE_URL") != base_url:
        raise RouteError("OPENAI_BASE_URL does not point at the auditor guard")
    return base_url, token


def _is_loopback(url: str) -> bool:
    parts = urllib.parse.urlsplit(url)
    return parts.scheme in ("http", "https") and (parts.hostname or "") in LOOPBACK_HOSTS


# ---------------------------------------------------------------------------
# 2. Budget guard
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Price:
    input_per_million: Decimal
    output_per_million: Decimal
    # None: no cached price is listed, so cached input is charged as uncached.
    cached_input_per_million: Decimal | None = None

    def cost(self, prompt_tokens: int, completion_tokens: int) -> Decimal:
        return (
            Decimal(prompt_tokens) * self.input_per_million
            + Decimal(completion_tokens) * self.output_per_million
        ) / Decimal(1_000_000)

    def cost_with_cache(self, prompt_tokens: int, cached_tokens: int, completion_tokens: int) -> Decimal:
        """Cost when ``cached_tokens`` of ``prompt_tokens`` were cache hits."""
        cached = max(0, min(int(cached_tokens), int(prompt_tokens)))
        rate = self.input_per_million if self.cached_input_per_million is None else self.cached_input_per_million
        return (
            Decimal(prompt_tokens - cached) * self.input_per_million
            + Decimal(cached) * rate
            + Decimal(completion_tokens) * self.output_per_million
        ) / Decimal(1_000_000)


DEEPSEEK_PRICE = Price(
    Decimal(PRICE_SNAPSHOT["input_per_million"]), Decimal(PRICE_SNAPSHOT["output_per_million"])
)


def _usd(value: Decimal) -> str:
    return format(value.quantize(Decimal("0.00000001"), rounding=ROUND_HALF_UP), "f")


@dataclass(frozen=True)
class ModelSpec:
    """One exact model id an exact-model provider may serve, with its price."""

    model: str
    kind: str  # "chat" or "embedding"
    price: Price


def _price_field(entry: Mapping[str, Any], name: str, model: str, required: bool) -> Decimal | None:
    value = entry.get(name)
    if value is None:
        if required:
            raise RouteError(f"model {model} has no {name} in providers.json; paid stages refuse it")
        return None
    if not isinstance(value, str):
        raise RouteError(f"providers.json {model}.{name} must be a decimal string or null")
    try:
        price = Decimal(value)
    except Exception:  # noqa: BLE001
        raise RouteError(f"providers.json {model}.{name} is not a number") from None
    if not price.is_finite() or price < 0:
        raise RouteError(f"providers.json {model}.{name} must be a finite non-negative number")
    return price


def load_providers(path: Path | None = None) -> dict[str, Any]:
    """Load and validate ``common/providers.json``.

    The DeepSeek entry must mirror the constants in this file; the DeepSeek route
    itself never reads the table, so its behaviour cannot drift with it.
    """
    path = PROVIDERS_PATH if path is None else Path(path)
    try:
        table = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RouteError(f"provider table not found: {path}") from None
    except json.JSONDecodeError as error:
        raise RouteError(f"provider table {path} is not JSON: {error.msg}") from None
    if not isinstance(table, dict) or table.get("schema") != SCHEMA_PROVIDERS:
        raise RouteError(f"{path} schema must be {SCHEMA_PROVIDERS}")
    providers = table.get("providers")
    if not isinstance(providers, dict) or set(providers) != set(PAID_PROVIDERS):
        raise RouteError(f"{path} must describe exactly the providers {list(PAID_PROVIDERS)}")
    deepseek = providers["deepseek"]
    snapshot = deepseek.get("price_snapshot") or {}
    if (deepseek.get("base_url"), deepseek.get("key_env"), deepseek.get("upstream_model"),
            snapshot.get("snapshot_id"), snapshot.get("input_per_million"), snapshot.get("output_per_million")) != (
            DEEPSEEK_BASE_URL, DEEPSEEK_KEY_ENV, DEEPSEEK_MODEL, PRICE_SNAPSHOT["snapshot_id"],
            PRICE_SNAPSHOT["input_per_million"], PRICE_SNAPSHOT["output_per_million"]):
        raise RouteError(f"{path} deepseek entry does not mirror the DeepSeek constants in deepseek_route.py")
    openai_entry = providers["openai"]
    if (openai_entry.get("base_url"), openai_entry.get("key_env"), openai_entry.get("model_policy")) != (
            OPENAI_BASE_URL, OPENAI_KEY_ENV, "exact"):
        raise RouteError(f"{path} openai entry must use {OPENAI_BASE_URL}, {OPENAI_KEY_ENV} and model_policy exact")
    if sorted(openai_entry.get("endpoints") or []) != ["chat.completions", "embeddings"]:
        raise RouteError(f"{path} openai endpoints must be chat.completions and embeddings")
    models = openai_entry.get("models")
    if not isinstance(models, dict) or not models:
        raise RouteError(f"{path} openai entry needs a models table")
    for name, entry in models.items():
        if not isinstance(entry, dict) or entry.get("kind") not in ("chat", "embedding"):
            raise RouteError(f"{path} model {name}: kind must be chat or embedding")
    return table


def provider_models(table: Mapping[str, Any], provider: str, model_ids: Iterable[str]) -> dict[str, ModelSpec]:
    """Priced ``ModelSpec`` for each id, or RouteError for an unknown or unpriced model."""
    if provider != "openai":
        raise RouteError(f"provider {provider!r} has no exact-model table")
    known = table["providers"]["openai"]["models"]
    specs: dict[str, ModelSpec] = {}
    for model in model_ids:
        entry = known.get(model)
        if entry is None:
            raise RouteError(f"model {model!r} is not in the {provider} table of providers.json; "
                             "only exact, priced model ids may be used")
        kind = entry["kind"]
        input_price = _price_field(entry, "input_per_million", model, required=True)
        output_price = _price_field(entry, "output_per_million", model, required=kind == "chat")
        cached_price = _price_field(entry, "cached_input_per_million", model, required=False)
        if kind == "embedding" and output_price not in (None, Decimal(0)):
            raise RouteError(f"providers.json {model}: embeddings have input tokens only")
        specs[model] = ModelSpec(model, kind, Price(input_price, output_price or Decimal(0), cached_price))
    return specs


def price_snapshot_for(table: Mapping[str, Any], provider: str, specs: Mapping[str, ModelSpec]) -> dict[str, Any]:
    """Receipt record of the prices a non-DeepSeek stage was charged at."""
    pricing = table["providers"][provider].get("pricing") or {}
    return {
        "provider": provider,
        "currency": pricing.get("currency", "USD"),
        "unit": pricing.get("unit"),
        "tier": pricing.get("tier"),
        "fetched": pricing.get("fetched"),
        "sources": pricing.get("sources"),
        "cached_input_policy": pricing.get("cached_input_policy"),
        "models": {
            name: {
                "kind": spec.kind,
                "input_per_million": str(spec.price.input_per_million),
                "cached_input_per_million": None if spec.price.cached_input_per_million is None
                else str(spec.price.cached_input_per_million),
                "output_per_million": str(spec.price.output_per_million),
            }
            for name, spec in specs.items()
        },
    }


@dataclass
class GuardConfig:
    stage_id: str
    ledger_path: Path
    cap_usd: Decimal
    cap_tokens: int
    cap_requests: int | None = None
    upstream: str = "deepseek"  # "deepseek" or "ollama"
    upstream_base_url: str = DEEPSEEK_BASE_URL
    upstream_model: str = DEEPSEEK_MODEL
    request_model: str = DEEPSEEK_MODEL
    model_aliases: tuple[str, ...] = ()
    api_key: str | None = field(default=None, repr=False)
    client_token: str = field(default_factory=lambda: secrets.token_urlsafe(24), repr=False)
    max_tokens_default: int = 2048
    max_tokens_ceiling: int = 4096
    request_timeout_s: float = 120.0
    prompt_bytes_per_token: float = 2.0
    max_consecutive_upstream_errors: int = 8
    embeddings_base_url: str | None = None
    embeddings_model: str | None = None
    price: Price = DEEPSEEK_PRICE
    # Exact-model providers (openai): the allowlist, each id with its price.
    models: Mapping[str, ModelSpec] = field(default_factory=dict)

    def validate(self) -> None:
        if not isinstance(self.cap_usd, Decimal) or self.cap_usd <= 0:
            raise RouteError("cap_usd must be a positive Decimal")
        if self.cap_tokens <= 0:
            raise RouteError("cap_tokens must be positive")
        if self.cap_requests is not None and self.cap_requests <= 0:
            raise RouteError("cap_requests must be positive when set")
        if self.upstream != "openai" and self.models:
            raise RouteError("an exact model allowlist is only for the openai upstream")
        if self.upstream == "openai":
            if self.upstream_base_url != OPENAI_BASE_URL and not _is_loopback(self.upstream_base_url):
                raise RouteError("openai upstream must be https://api.openai.com/v1 (or a loopback test double)")
            if not self.api_key:
                raise RouteError("openai upstream needs an API key")
            if not self.models:
                raise RouteError("openai upstream needs an exact model allowlist")
            if self.model_aliases:
                raise RouteError("openai upstream never rewrites the model; model_aliases must be empty")
            for name, spec in self.models.items():
                if not isinstance(spec, ModelSpec) or spec.model != name or spec.kind not in ("chat", "embedding"):
                    raise RouteError(f"invalid model spec for {name!r}")
            if self.request_model not in self.models:
                raise RouteError("request_model must be one of the allowed openai models")
            if self.embeddings_base_url is not None or self.embeddings_model is not None:
                raise RouteError("openai stages use the provider's own embeddings endpoint, not local_embeddings")
        elif self.upstream == "deepseek":
            if self.upstream_base_url != DEEPSEEK_BASE_URL and not _is_loopback(self.upstream_base_url):
                raise RouteError("deepseek upstream must be https://api.deepseek.com (or a loopback test double)")
            if self.upstream_model != DEEPSEEK_MODEL:
                raise RouteError(f"deepseek upstream model must be {DEEPSEEK_MODEL}")
            if not self.api_key:
                raise RouteError("deepseek upstream needs an API key")
        elif self.upstream == "ollama":
            if not _is_loopback(self.upstream_base_url):
                raise RouteError("ollama upstream must be a loopback URL")
            if self.api_key:
                raise RouteError("refusing to send an API key to a dry-run upstream")
        else:
            raise RouteError(f"unknown upstream {self.upstream!r}")
        if self.embeddings_base_url is not None:
            if not _is_loopback(self.embeddings_base_url) or not self.embeddings_model:
                raise RouteError("embeddings may only go to a declared loopback model")
        if not 1 <= self.max_tokens_default <= self.max_tokens_ceiling:
            raise RouteError("need 1 <= max_tokens_default <= max_tokens_ceiling")
        if self.prompt_bytes_per_token <= 0:
            raise RouteError("prompt_bytes_per_token must be positive")


@dataclass
class _Prepared:
    request_id: str
    body: bytes
    stream: bool
    requested_model: str
    max_tokens: int
    clamped: bool
    n: int
    dropped: list[str]
    normalised: dict[str, int]
    tools: int
    messages: int
    est_prompt: int
    est_completion: int
    est_usd: Decimal
    started: float
    # Exact-model providers only.
    endpoint: str = "chat.completions"
    price: Price | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class _Refusal(Exception):
    def __init__(self, status: int, code: str, message: str, extra: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.extra = extra or {}


class BudgetGuard:
    """OpenAI-compatible proxy on 127.0.0.1 with hard token/USD/request caps."""

    def __init__(self, config: GuardConfig) -> None:
        config.validate()
        self.config = config
        self._lock = threading.Lock()
        self._seq = 0
        self.requests = 0
        self.refused = 0
        self.embedding_requests = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.spent_usd = Decimal(0)
        self.estimated_charges = 0
        self._reserved_tokens = 0
        self._reserved_usd = Decimal(0)
        self._inflight = 0
        self._consecutive_errors = 0
        self.halt_reason: str | None = None
        # True once a request was refused for budget reasons or a fatal error
        # halted the guard.  Merely reaching a cap with the last allowed
        # response does not set it, so a child can finish its own bookkeeping.
        self.stop_child = False
        # Exact-model providers only (reported in their summaries).
        self.embedding_prompt_tokens = 0
        self.cached_tokens = 0
        self.reasoning_tokens = 0
        self.response_model_mismatches = 0
        self.logprobs_responses = 0
        self.upstream_error_responses = 0
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        config.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self._ledger = config.ledger_path.open("a", encoding="utf-8", newline="\n")
        if _is_loopback(config.upstream_base_url):
            self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        else:
            self._opener = urllib.request.build_opener()
        self._local_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    # -- lifecycle -----------------------------------------------------------
    @property
    def halted(self) -> bool:
        return self.halt_reason is not None

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RouteError("guard not started")
        return f"http://127.0.0.1:{self._server.server_address[1]}/v1"

    def start(self, port: int = 0) -> str:
        server = _GuardServer(("127.0.0.1", port), _GuardHandler)
        server.guard = self  # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="auditor-guard", daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=10)
        with self._lock:
            if not self._ledger.closed:
                self._ledger.close()

    def __enter__(self) -> BudgetGuard:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def summary(self) -> dict[str, Any]:
        with self._lock:
            result = {
                "stage_id": self.config.stage_id,
                "upstream": self.config.upstream,
                "upstream_base_url": self.config.upstream_base_url,
                "upstream_model": self.config.upstream_model,
                "request_model": self.config.request_model,
                "model_aliases": list(self.config.model_aliases),
                "requests_forwarded": self.requests,
                "requests_refused": self.refused,
                "embedding_requests": self.embedding_requests,
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens": self.total_tokens,
                "usd": _usd(self.spent_usd),
                "usd_is_notional": self.config.upstream not in PAID_PROVIDERS,
                "estimated_charges": self.estimated_charges,
                "cap_usd": _usd(self.config.cap_usd),
                "cap_tokens": self.config.cap_tokens,
                "cap_requests": self.config.cap_requests,
                "halted": self.halted,
                "halt_reason": self.halt_reason,
                "stop_child": self.stop_child,
                "ledger": str(self.config.ledger_path),
            }
            if self.config.upstream == "openai":
                result.update({
                    "upstream_model": None,
                    "model_policy": "exact (never rewritten)",
                    "allowed_models": {name: spec.kind for name, spec in self.config.models.items()},
                    "embedding_prompt_tokens": self.embedding_prompt_tokens,
                    "cached_tokens": self.cached_tokens,
                    "reasoning_tokens": self.reasoning_tokens,
                    "logprobs_responses": self.logprobs_responses,
                    "response_model_mismatches": self.response_model_mismatches,
                    "requests_include_embeddings": True,
                    "upstream_error_responses": self.upstream_error_responses,
                    "upstream_error_billing": "charged as 0 USD (UNVERIFIED that OpenAI never bills an HTTP "
                                              "4xx/5xx; reconcile with the usage dashboard, RUN-PLAN-OPENAI.md O13)",
                })
            return result

    # -- accounting ----------------------------------------------------------
    def _halt(self, reason: str, fatal: bool = False) -> None:
        if self.halt_reason is None:
            self.halt_reason = reason
        if fatal:
            self.stop_child = True

    def _write(self, record: dict[str, Any]) -> None:
        self._seq += 1
        line = {
            "schema": SCHEMA_LEDGER,
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "stage": self.config.stage_id,
            "upstream": self.config.upstream,
            **record,
            "cum_prompt_tokens": self.prompt_tokens,
            "cum_completion_tokens": self.completion_tokens,
            "cum_usd": _usd(self.spent_usd),
            "halted": self.halted,
            "halt_reason": self.halt_reason,
        }
        self._ledger.write(json.dumps(line, sort_keys=True) + "\n")
        self._ledger.flush()
        os.fsync(self._ledger.fileno())

    def refuse(self, status: int, code: str, message: str, requested_model: str | None = None,
               endpoint: str = "chat.completions", extra: dict[str, Any] | None = None) -> None:
        with self._lock:
            self.refused += 1
            if status == 402:
                self.stop_child = True
            self._write(
                {
                    "request_id": uuid.uuid4().hex,
                    "endpoint": endpoint,
                    "outcome": "refused",
                    "refusal": code,
                    "http_status": status,
                    "requested_model": (requested_model or "")[:120] or None,
                    **(extra or {}),
                }
            )

    def prepare_chat(self, raw: bytes) -> _Prepared:
        """Validate, normalise and reserve budget.  Raises _Refusal."""
        if self.config.upstream == "openai":
            return self._prepare_openai_chat(raw)
        try:
            body = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise _Refusal(400, "invalid_json", "request body is not JSON") from None
        if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
            raise _Refusal(400, "invalid_request", "chat request needs a messages list")
        cfg = self.config
        requested_model = str(body.get("model") or "")
        allowed = {cfg.request_model, *cfg.model_aliases}
        if requested_model not in allowed:
            raise _Refusal(400, "model_not_allowed", f"model must be one of {sorted(allowed)}")
        body["model"] = cfg.upstream_model
        body["thinking"] = dict(THINKING_DISABLED)
        dropped = [name for name in DROPPED_FIELDS if name in body]
        for name in dropped:
            body.pop(name)
        clamped = False
        limit = body.pop("max_completion_tokens", None)
        if limit is not None:
            dropped.append("max_completion_tokens->max_tokens")
        for candidate in (body.get("max_tokens"), limit):
            if candidate is not None and not (isinstance(candidate, int) and not isinstance(candidate, bool) and candidate > 0):
                raise _Refusal(400, "invalid_max_tokens", "max_tokens must be a positive integer")
        given = [value for value in (body.get("max_tokens"), limit) if value is not None]
        max_tokens = min(given) if given else cfg.max_tokens_default
        if max_tokens > cfg.max_tokens_ceiling:
            max_tokens, clamped = cfg.max_tokens_ceiling, True
        body["max_tokens"] = max_tokens
        n = body.get("n", 1)
        if n is None:
            n = 1
        if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= 8:
            raise _Refusal(400, "invalid_n", "n must be an integer between 1 and 8")
        stream = bool(body.get("stream"))
        if stream:
            options = body.get("stream_options") if isinstance(body.get("stream_options"), dict) else {}
            body["stream_options"] = {**options, "include_usage": True}
        else:
            body.pop("stream_options", None)
        normalised = _normalise_messages(body["messages"])
        tools = body.get("tools") if isinstance(body.get("tools"), list) else []
        encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        est_prompt = math.ceil(len(encoded) / cfg.prompt_bytes_per_token)
        est_completion = max_tokens * n
        est_usd = cfg.price.cost(est_prompt, est_completion)
        with self._lock:
            estimate = {
                "est_prompt_tokens": est_prompt,
                "est_completion_tokens": est_completion,
                "est_usd": _usd(est_usd),
                "committed_tokens": self.total_tokens + self._reserved_tokens,
                "committed_usd": _usd(self.spent_usd + self._reserved_usd),
            }
            if self.halted:
                raise _Refusal(402, "guard_halted", f"stage budget guard halted: {self.halt_reason}", estimate)
            if cfg.cap_requests is not None and self.requests + self._inflight >= cfg.cap_requests:
                self._halt("request_cap_reached")
                raise _Refusal(402, "request_cap", f"stage request cap {cfg.cap_requests} reached", estimate)
            committed_tokens = self.total_tokens + self._reserved_tokens
            if committed_tokens + est_prompt + est_completion > cfg.cap_tokens:
                self._halt("token_cap_preflight")
                raise _Refusal(402, "token_cap", "request would exceed the stage token cap", estimate)
            if self.spent_usd + self._reserved_usd + est_usd > cfg.cap_usd:
                self._halt("usd_cap_preflight")
                raise _Refusal(402, "usd_cap", "request would exceed the stage USD cap", estimate)
            self._reserved_tokens += est_prompt + est_completion
            self._reserved_usd += est_usd
            self._inflight += 1
        return _Prepared(
            request_id=uuid.uuid4().hex,
            body=encoded,
            stream=stream,
            requested_model=requested_model[:120],
            max_tokens=max_tokens,
            clamped=clamped,
            n=n,
            dropped=dropped,
            normalised=normalised,
            tools=len(tools),
            messages=len(body["messages"]),
            est_prompt=est_prompt,
            est_completion=est_completion,
            est_usd=est_usd,
            started=time.monotonic(),
        )

    # -- exact-model providers (openai) -----------------------------------------
    def _reserve(self, est_prompt: int, est_completion: int, est_usd: Decimal) -> None:
        """Pre-flight cap checks and reservation shared by both openai endpoints."""
        cfg = self.config
        with self._lock:
            estimate = {
                "est_prompt_tokens": est_prompt,
                "est_completion_tokens": est_completion,
                "est_usd": _usd(est_usd),
                "committed_tokens": self.total_tokens + self._reserved_tokens,
                "committed_usd": _usd(self.spent_usd + self._reserved_usd),
            }
            if self.halted:
                raise _Refusal(402, "guard_halted", f"stage budget guard halted: {self.halt_reason}", estimate)
            if cfg.cap_requests is not None and self.requests + self._inflight >= cfg.cap_requests:
                self._halt("request_cap_reached")
                raise _Refusal(402, "request_cap", f"stage request cap {cfg.cap_requests} reached", estimate)
            committed_tokens = self.total_tokens + self._reserved_tokens
            if committed_tokens + est_prompt + est_completion > cfg.cap_tokens:
                self._halt("token_cap_preflight")
                raise _Refusal(402, "token_cap", "request would exceed the stage token cap", estimate)
            if self.spent_usd + self._reserved_usd + est_usd > cfg.cap_usd:
                self._halt("usd_cap_preflight")
                raise _Refusal(402, "usd_cap", "request would exceed the stage USD cap", estimate)
            self._reserved_tokens += est_prompt + est_completion
            self._reserved_usd += est_usd
            self._inflight += 1

    def _model_spec(self, body: Mapping[str, Any], kind: str) -> tuple[str, ModelSpec]:
        requested_model = str(body.get("model") or "")
        spec = self.config.models.get(requested_model)
        if spec is None or spec.kind != kind:
            allowed = sorted(name for name, s in self.config.models.items() if s.kind == kind)
            raise _Refusal(400, "model_not_allowed",
                           f"model must be one of {allowed} (exact ids; this guard never rewrites the model)")
        return requested_model, spec

    def _prepare_openai_chat(self, raw: bytes) -> _Prepared:
        try:
            body = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise _Refusal(400, "invalid_json", "request body is not JSON") from None
        if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
            raise _Refusal(400, "invalid_request", "chat request needs a messages list")
        cfg = self.config
        requested_model, spec = self._model_spec(body, "chat")
        for name in OPENAI_REFUSED_FIELDS:
            if name in body:
                raise _Refusal(400, "field_not_allowed", f"field {name!r} is not allowed on the openai route")
        if body.get("modalities") not in (None, ["text"]):
            raise _Refusal(400, "field_not_allowed", "only text modalities are priced on the openai route")
        if body.get("service_tier") not in (None, "default"):
            raise _Refusal(400, "service_tier_not_allowed",
                           "service_tier must be omitted or 'default' (prices are Standard tier only)")
        for message in body["messages"]:
            content = message.get("content") if isinstance(message, dict) else None
            if isinstance(content, list):
                for part in content:
                    kind = part.get("type") if isinstance(part, dict) else None
                    if kind not in OPENAI_TEXT_PART_TYPES:
                        # Image, audio and file parts are billed by rules the pre-flight
                        # byte estimate does not model (an image_url part estimated at 88 tokens).
                        raise _Refusal(400, "content_part_not_allowed",
                                       f"content part type {str(kind)[:40]!r} is not allowed on the openai route "
                                       f"(only {list(OPENAI_TEXT_PART_TYPES)})")
        limit_fields = [name for name in ("max_tokens", "max_completion_tokens") if body.get(name) is not None]
        for name in limit_fields:
            value = body[name]
            if not (isinstance(value, int) and not isinstance(value, bool) and value > 0):
                raise _Refusal(400, "invalid_max_tokens", f"{name} must be a positive integer")
        clamped = False
        for name in limit_fields:
            if body[name] > cfg.max_tokens_ceiling:
                body[name], clamped = cfg.max_tokens_ceiling, True
        if limit_fields:
            field_used = limit_fields[0] if len(limit_fields) == 1 else "both"
            max_tokens = max(body[name] for name in limit_fields)
        else:
            body["max_completion_tokens"] = cfg.max_tokens_default
            field_used, max_tokens = "default:max_completion_tokens", cfg.max_tokens_default
        n = body.get("n", 1)
        if n is None:
            n = 1
        if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= 8:
            raise _Refusal(400, "invalid_n", "n must be an integer between 1 and 8")
        logprobs = body.get("logprobs")
        if logprobs is not None and not isinstance(logprobs, bool):
            raise _Refusal(400, "invalid_logprobs", "logprobs must be a boolean")
        top_logprobs = body.get("top_logprobs")
        if top_logprobs is not None and not (
            isinstance(top_logprobs, int) and not isinstance(top_logprobs, bool)
            and 0 <= top_logprobs <= OPENAI_TOP_LOGPROBS_MAX
        ):
            raise _Refusal(400, "invalid_top_logprobs", f"top_logprobs must be an integer 0-{OPENAI_TOP_LOGPROBS_MAX}")
        dropped: list[str] = []
        stream = bool(body.get("stream"))
        if stream:
            options = body.get("stream_options") if isinstance(body.get("stream_options"), dict) else {}
            body["stream_options"] = {**options, "include_usage": True}
        elif "stream_options" in body:
            body.pop("stream_options")
            dropped.append("stream_options(no stream)")
        tools = body.get("tools") if isinstance(body.get("tools"), list) else []
        effort = body.get("reasoning_effort")
        encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        est_prompt = math.ceil(len(encoded) / cfg.prompt_bytes_per_token)
        est_completion = max_tokens * n
        est_usd = spec.price.cost(est_prompt, est_completion)
        self._reserve(est_prompt, est_completion, est_usd)
        return _Prepared(
            request_id=uuid.uuid4().hex,
            body=encoded,
            stream=stream,
            requested_model=requested_model[:120],
            max_tokens=max_tokens,
            clamped=clamped,
            n=n,
            dropped=dropped,
            normalised={},
            tools=len(tools),
            messages=len(body["messages"]),
            est_prompt=est_prompt,
            est_completion=est_completion,
            est_usd=est_usd,
            started=time.monotonic(),
            endpoint="chat.completions",
            price=spec.price,
            extra={
                "max_tokens_field": field_used,
                "logprobs": logprobs,
                "top_logprobs": top_logprobs,
                "reasoning_effort": effort if isinstance(effort, str) else None,
            },
        )

    def prepare_embeddings(self, raw: bytes) -> _Prepared:
        """Embeddings on an exact-model provider: allowlist, reserve, forward unchanged."""
        try:
            body = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise _Refusal(400, "invalid_json", "request body is not JSON") from None
        if not isinstance(body, dict):
            raise _Refusal(400, "invalid_request", "embeddings request must be a JSON object")
        requested_model, spec = self._model_spec(body, "embedding")
        inputs = body.get("input")
        if inputs is None or inputs == "" or (isinstance(inputs, list) and not inputs):
            raise _Refusal(400, "invalid_request", "embeddings request needs a non-empty input")
        encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        est_prompt = math.ceil(len(encoded) / self.config.prompt_bytes_per_token)
        est_usd = spec.price.cost(est_prompt, 0)
        self._reserve(est_prompt, 0, est_usd)
        return _Prepared(
            request_id=uuid.uuid4().hex,
            body=encoded,
            stream=False,
            requested_model=requested_model[:120],
            max_tokens=0,
            clamped=False,
            n=1,
            dropped=[],
            normalised={},
            tools=0,
            messages=0,
            est_prompt=est_prompt,
            est_completion=0,
            est_usd=est_usd,
            started=time.monotonic(),
            endpoint="embeddings",
            price=spec.price,
            extra={"inputs": len(inputs) if isinstance(inputs, list) else 1},
        )

    def _finish_exact(self, prep: _Prepared, *, outcome: str, http_status: int, usage: Mapping[str, Any] | None,
                      upstream_id: str | None, finish_reason: str | None,
                      response_meta: Mapping[str, Any] | None) -> None:
        cfg = self.config
        meta = response_meta or {}
        embeddings = prep.endpoint == "embeddings"
        price = prep.price or cfg.price
        with self._lock:
            self._reserved_tokens -= prep.est_prompt + prep.est_completion
            self._reserved_usd -= prep.est_usd
            self._inflight -= 1
            self.requests += 1
            if embeddings:
                self.embedding_requests += 1
            prompt = completion = cached = 0
            reasoning = None
            source = "none"
            if outcome == "ok" and usage and isinstance(usage.get("prompt_tokens"), int):
                prompt = int(usage.get("prompt_tokens") or 0)
                if not embeddings:
                    completion = int(usage.get("completion_tokens") or 0)
                    details = usage.get("prompt_tokens_details")
                    if isinstance(details, Mapping) and isinstance(details.get("cached_tokens"), int):
                        cached = int(details["cached_tokens"])
                    completion_details = usage.get("completion_tokens_details")
                    if isinstance(completion_details, Mapping):
                        reasoning = completion_details.get("reasoning_tokens")
                source = "provider"
                self._consecutive_errors = 0
            elif outcome in ("ok", "transport_error"):
                # Unknown usage may still be billed: charge the reservation, uncached.
                prompt, completion, source = prep.est_prompt, prep.est_completion, "estimate"
                self.estimated_charges += 1
                if outcome == "ok":
                    self._halt("usage_missing", fatal=True)
                    self._consecutive_errors = 0
                else:
                    self._consecutive_errors += 1
            else:
                # An upstream HTTP error is charged 0 USD here.  UNVERIFIED for OpenAI:
                # the count is reported so the dashboard reconciliation (O13) can check it.
                self.upstream_error_responses += 1
                self._consecutive_errors += 1
                if http_status in (401, 402, 403):
                    self._halt(f"upstream_http_{http_status}", fatal=True)
            if self._consecutive_errors >= cfg.max_consecutive_upstream_errors:
                self._halt("consecutive_upstream_errors", fatal=True)
            cost = price.cost_with_cache(prompt, cached, completion)
            uncached_cost = price.cost(prompt, completion)
            self.prompt_tokens += prompt
            self.completion_tokens += completion
            self.spent_usd += cost
            self.cached_tokens += cached
            if embeddings:
                self.embedding_prompt_tokens += prompt
            if isinstance(reasoning, int) and not isinstance(reasoning, bool):
                self.reasoning_tokens += reasoning
            response_model = meta.get("model")
            response_model = str(response_model)[:120] if response_model is not None else None
            model_matches = None if response_model is None else response_model == prep.requested_model
            if model_matches is False:
                self.response_model_mismatches += 1
            logprobs_returned = meta.get("logprobs_returned")
            if logprobs_returned:
                self.logprobs_responses += 1
            tier = meta.get("service_tier")
            if outcome == "ok" and tier not in (None, "default"):
                # Prices in providers.json are Standard tier only.
                self._halt("service_tier_" + re.sub(r"[^a-z0-9]+", "_", str(tier).lower())[:32], fatal=True)
            if self.total_tokens >= cfg.cap_tokens:
                self._halt("token_cap_reached")
            if self.spent_usd >= cfg.cap_usd:
                self._halt("usd_cap_reached")
            if cfg.cap_requests is not None and self.requests >= cfg.cap_requests:
                self._halt("request_cap_reached")
            record: dict[str, Any] = {
                "request_id": prep.request_id,
                "upstream_id": upstream_id,
                "endpoint": prep.endpoint,
                "outcome": outcome,
                "http_status": http_status,
                "requested_model": prep.requested_model,
                "upstream_model": prep.requested_model,
                "response_model": response_model,
                "response_model_matches": model_matches,
                "service_tier": None if tier is None else str(tier)[:32],
                "request_sha256": hashlib.sha256(prep.body).hexdigest(),
                "usage_source": source,
                "prompt_tokens": prompt,
                "completion_tokens": completion,
                "cached_tokens": cached,
                "est_prompt_tokens": prep.est_prompt,
                "est_completion_tokens": prep.est_completion,
                "usd": _usd(cost),
                "usd_uncached_basis": _usd(uncached_cost),
                "counts_toward_caps": True,
                "latency_ms": int((time.monotonic() - prep.started) * 1000),
            }
            if embeddings:
                record["inputs"] = prep.extra.get("inputs")
            else:
                record.update(
                    {
                        "stream": prep.stream,
                        "n": prep.n,
                        "max_tokens": prep.max_tokens,
                        "max_tokens_clamped": prep.clamped,
                        "max_tokens_field": prep.extra.get("max_tokens_field"),
                        "dropped_fields": prep.dropped,
                        "messages": prep.messages,
                        "tools": prep.tools,
                        "finish_reason": finish_reason,
                        "reasoning_tokens": reasoning,
                        "reasoning_effort": prep.extra.get("reasoning_effort"),
                        "logprobs": prep.extra.get("logprobs"),
                        "top_logprobs": prep.extra.get("top_logprobs"),
                        "logprobs_returned": logprobs_returned,
                        "stream_error": meta.get("stream_error"),
                    }
                )
            self._write(record)

    def finish(self, prep: _Prepared, *, outcome: str, http_status: int, usage: Mapping[str, Any] | None,
               upstream_id: str | None = None, finish_reason: str | None = None,
               response_meta: Mapping[str, Any] | None = None) -> None:
        cfg = self.config
        if cfg.upstream == "openai":
            self._finish_exact(prep, outcome=outcome, http_status=http_status, usage=usage,
                               upstream_id=upstream_id, finish_reason=finish_reason, response_meta=response_meta)
            return
        with self._lock:
            self._reserved_tokens -= prep.est_prompt + prep.est_completion
            self._reserved_usd -= prep.est_usd
            self._inflight -= 1
            self.requests += 1
            prompt = completion = 0
            source = "none"
            cache_hit = cache_miss = reasoning = None
            if outcome == "ok" and usage and isinstance(usage.get("prompt_tokens"), int):
                prompt = int(usage.get("prompt_tokens") or 0)
                completion = int(usage.get("completion_tokens") or 0)
                cache_hit = usage.get("prompt_cache_hit_tokens")
                cache_miss = usage.get("prompt_cache_miss_tokens")
                details = usage.get("completion_tokens_details")
                if isinstance(details, Mapping):
                    reasoning = details.get("reasoning_tokens")
                source = "provider"
                self._consecutive_errors = 0
            elif outcome in ("ok", "transport_error"):
                # Unknown usage may still be billed: charge the reservation.
                prompt, completion, source = prep.est_prompt, prep.est_completion, "estimate"
                self.estimated_charges += 1
                if outcome == "ok":
                    self._halt("usage_missing", fatal=True)
                    self._consecutive_errors = 0
                else:
                    self._consecutive_errors += 1
            else:
                self._consecutive_errors += 1
                if http_status in (401, 402, 403):
                    self._halt(f"upstream_http_{http_status}", fatal=True)
            if self._consecutive_errors >= cfg.max_consecutive_upstream_errors:
                self._halt("consecutive_upstream_errors", fatal=True)
            cost = cfg.price.cost(prompt, completion)
            self.prompt_tokens += prompt
            self.completion_tokens += completion
            self.spent_usd += cost
            if self.total_tokens >= cfg.cap_tokens:
                self._halt("token_cap_reached")
            if self.spent_usd >= cfg.cap_usd:
                self._halt("usd_cap_reached")
            if cfg.cap_requests is not None and self.requests >= cfg.cap_requests:
                self._halt("request_cap_reached")
            self._write(
                {
                    "request_id": prep.request_id,
                    "upstream_id": upstream_id,
                    "endpoint": "chat.completions",
                    "outcome": outcome,
                    "http_status": http_status,
                    "requested_model": prep.requested_model,
                    "upstream_model": cfg.upstream_model,
                    "stream": prep.stream,
                    "n": prep.n,
                    "max_tokens": prep.max_tokens,
                    "max_tokens_clamped": prep.clamped,
                    "dropped_fields": prep.dropped,
                    "normalised": prep.normalised,
                    "messages": prep.messages,
                    "tools": prep.tools,
                    "request_sha256": hashlib.sha256(prep.body).hexdigest(),
                    "finish_reason": finish_reason,
                    "usage_source": source,
                    "prompt_tokens": prompt,
                    "completion_tokens": completion,
                    "cache_hit_tokens": cache_hit,
                    "cache_miss_tokens": cache_miss,
                    "reasoning_tokens": reasoning,
                    "est_prompt_tokens": prep.est_prompt,
                    "est_completion_tokens": prep.est_completion,
                    "usd": _usd(cost),
                    "latency_ms": int((time.monotonic() - prep.started) * 1000),
                }
            )

    def record_embeddings(self, *, outcome: str, http_status: int, usage: Mapping[str, Any] | None,
                          inputs: int, requested_model: str, started: float) -> None:
        with self._lock:
            self.embedding_requests += 1
            tokens = usage.get("prompt_tokens") if isinstance(usage, Mapping) else None
            self._write(
                {
                    "request_id": uuid.uuid4().hex,
                    "endpoint": "embeddings",
                    "outcome": outcome,
                    "http_status": http_status,
                    "requested_model": requested_model[:120],
                    "upstream_model": self.config.embeddings_model,
                    "embedding_upstream": self.config.embeddings_base_url,
                    "inputs": inputs,
                    "prompt_tokens": tokens if isinstance(tokens, int) else None,
                    "usd": "0.00000000",
                    "counts_toward_caps": False,
                    "latency_ms": int((time.monotonic() - started) * 1000),
                }
            )

    # -- upstream ------------------------------------------------------------
    def open_upstream(self, prep: _Prepared):
        cfg = self.config
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream" if prep.stream else "application/json",
            "User-Agent": "auditor-guard/1",
        }
        if cfg.api_key:
            headers["Authorization"] = f"Bearer {cfg.api_key}"
        route = "/embeddings" if prep.endpoint == "embeddings" else "/chat/completions"
        request = urllib.request.Request(
            cfg.upstream_base_url.rstrip("/") + route,
            data=prep.body,
            headers=headers,
            method="POST",
        )
        return self._opener.open(request, timeout=cfg.request_timeout_s)


def _normalise_messages(messages: list[Any]) -> dict[str, int]:
    """Apply the lab adapter's DeepSeek wire normalisation in place."""
    counts = {"developer_to_system": 0, "tool_name_dropped": 0, "text_blocks_joined": 0}
    for message in messages:
        if not isinstance(message, dict):
            continue
        if message.get("role") == "developer":
            message["role"] = "system"
            counts["developer_to_system"] += 1
        if message.get("role") == "tool" and "name" in message:
            message.pop("name")
            counts["tool_name_dropped"] += 1
        content = message.get("content")
        if (
            isinstance(content, list)
            and content
            and all(isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str) for b in content)
        ):
            message["content"] = "\n".join(block["text"] for block in content)
            counts["text_blocks_joined"] += 1
    return counts


def _response_meta(parsed: Any) -> dict[str, Any]:
    """Served model, service tier and logprobs presence of a non-streamed response."""
    if not isinstance(parsed, dict):
        return {}
    choices = parsed.get("choices") or []
    return {
        "model": parsed.get("model"),
        "service_tier": parsed.get("service_tier"),
        "logprobs_returned": any(isinstance(c, dict) and c.get("logprobs") is not None for c in choices),
    }


def _error_body(code: str, message: str) -> bytes:
    return json.dumps(
        {"error": {"message": message, "type": "auditor_guard_refusal", "code": code}}
    ).encode("utf-8")


class _GuardServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        # A killed child drops its sockets; that is expected.  Anything else is
        # reported by exception type only, never with request content.
        error = sys.exc_info()[1]
        if isinstance(error, (ConnectionError, TimeoutError)):
            return
        print(f"auditor-guard: handler error {type(error).__name__}", file=sys.stderr)


class _GuardHandler(BaseHTTPRequestHandler):
    server_version = "auditor-guard/1"
    protocol_version = "HTTP/1.0"

    @property
    def guard(self) -> BudgetGuard:
        return self.server.guard  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        return  # the ledger is the log; never echo paths or bodies

    def _send(self, status: int, payload: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except OSError:
            pass

    def _authorised(self) -> bool:
        header = self.headers.get("Authorization", "")
        token = header[7:] if header.lower().startswith("bearer ") else ""
        return hmac.compare_digest(token.encode(), self.guard.config.client_token.encode())

    def _route(self) -> str:
        path = urllib.parse.urlsplit(self.path).path.rstrip("/")
        return path[3:] if path.startswith("/v1/") else path

    def do_GET(self) -> None:  # noqa: N802 - stdlib name
        route = self._route()
        if route == "/health":
            self._send(200, json.dumps({"ok": True, "halted": self.guard.halted}).encode())
            return
        if not self._authorised():
            self._send(401, _error_body("unauthorised", "missing or wrong guard token"))
            return
        if route == "/models":
            cfg = self.guard.config
            names = [cfg.request_model, *[a for a in cfg.model_aliases if a != cfg.request_model]]
            if cfg.upstream == "openai":
                names = [cfg.request_model, *[m for m in cfg.models if m != cfg.request_model]]
            data = [{"id": name, "object": "model", "owned_by": "auditor-guard"} for name in names]
            self._send(200, json.dumps({"object": "list", "data": data}).encode())
            return
        self._send(404, _error_body("not_found", "unsupported endpoint"))

    def do_POST(self) -> None:  # noqa: N802 - stdlib name
        route = self._route()
        guard = self.guard
        if not self._authorised():
            guard.refuse(401, "unauthorised", "missing or wrong guard token", endpoint=route)
            self._send(401, _error_body("unauthorised", "missing or wrong guard token"))
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            guard.refuse(413, "body_size", "request body missing or too large", endpoint=route)
            self._send(413, _error_body("body_size", "request body missing or too large"))
            return
        raw = self.rfile.read(length)
        if route == "/chat/completions":
            self._chat(raw)
        elif route == "/embeddings":
            self._embeddings(raw)
        else:
            guard.refuse(404, "unsupported_endpoint", "unsupported endpoint", endpoint=route)
            self._send(404, _error_body("unsupported_endpoint", f"unsupported endpoint {route}"))

    def _chat(self, raw: bytes) -> None:
        guard = self.guard
        try:
            prep = guard.prepare_chat(raw)
        except _Refusal as refusal:
            model = None
            try:
                model = str(json.loads(raw).get("model") or "")
            except Exception:  # noqa: BLE001 - the model name is optional ledger context
                pass
            guard.refuse(refusal.status, refusal.code, refusal.message, requested_model=model, extra=refusal.extra)
            self._send(refusal.status, _error_body(refusal.code, refusal.message))
            return
        try:
            response = guard.open_upstream(prep)
        except urllib.error.HTTPError as error:
            payload = error.read() if error.fp is not None else b""
            guard.finish(prep, outcome="upstream_error", http_status=error.code, usage=None)
            self._send(error.code, payload or _error_body("upstream_error", f"upstream HTTP {error.code}"))
            return
        except Exception as error:  # noqa: BLE001 - transport failures become 502
            guard.finish(prep, outcome="transport_error", http_status=502, usage=None)
            self._send(502, _error_body("upstream_transport", f"upstream transport error: {type(error).__name__}"))
            return
        with response:
            if prep.stream:
                self._relay_stream(prep, response)
            else:
                payload = response.read()
                usage, upstream_id, finish_reason = None, None, None
                meta = None
                try:
                    parsed = json.loads(payload)
                    usage = parsed.get("usage")
                    upstream_id = parsed.get("id")
                    choices = parsed.get("choices") or []
                    if choices and isinstance(choices[0], dict):
                        finish_reason = choices[0].get("finish_reason")
                    if guard.config.upstream == "openai":
                        meta = _response_meta(parsed)
                except Exception:  # noqa: BLE001 - unparseable body counts as missing usage
                    pass
                guard.finish(prep, outcome="ok", http_status=response.status, usage=usage,
                             upstream_id=upstream_id, finish_reason=finish_reason, response_meta=meta)
                self._send(response.status, payload)

    def _relay_stream(self, prep: _Prepared, response: Any) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        usage = upstream_id = finish_reason = None
        meta: dict[str, Any] = {"model": None, "service_tier": None, "logprobs_returned": False}
        client_open = True
        stream_error: str | None = None
        try:
            for line in response:
                if client_open:
                    try:
                        self.wfile.write(line)
                        self.wfile.flush()
                    except OSError:
                        client_open = False
                stripped = line.strip()
                if not stripped.startswith(b"data:"):
                    continue
                data = stripped[5:].strip()
                if data == b"[DONE]":
                    continue
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    continue
                if not isinstance(chunk, dict):
                    continue
                upstream_id = upstream_id or chunk.get("id")
                if isinstance(chunk.get("usage"), dict):
                    usage = chunk["usage"]
                for choice in chunk.get("choices") or []:
                    if isinstance(choice, dict) and choice.get("finish_reason"):
                        finish_reason = choice["finish_reason"]
                    if isinstance(choice, dict) and choice.get("logprobs") is not None:
                        meta["logprobs_returned"] = True
                meta["model"] = meta["model"] or chunk.get("model")
                meta["service_tier"] = chunk.get("service_tier") or meta["service_tier"]
        except Exception as error:  # noqa: BLE001 - an upstream that drops or stalls mid-stream
            # Without this, finish() never ran: no ledger row, the reservation and the
            # in-flight slot stayed held, and the spend was under-reported.
            stream_error = type(error).__name__
        exact = self.guard.config.upstream == "openai"
        if exact:
            meta["stream_error"] = stream_error
        if stream_error is not None and usage is None:
            # No provider usage arrived: charged at the reservation, like any transport error.
            self.guard.finish(prep, outcome="transport_error", http_status=502, usage=None,
                              upstream_id=upstream_id, finish_reason=finish_reason,
                              response_meta=meta if exact else None)
            return
        self.guard.finish(prep, outcome="ok", http_status=response.status, usage=usage,
                          upstream_id=upstream_id, finish_reason=finish_reason,
                          response_meta=meta if exact else None)

    def _exact_embeddings(self, raw: bytes) -> None:
        """Paid embeddings on an exact-model provider; charged against the stage caps."""
        guard = self.guard
        try:
            prep = guard.prepare_embeddings(raw)
        except _Refusal as refusal:
            model = None
            try:
                model = str(json.loads(raw).get("model") or "")
            except Exception:  # noqa: BLE001 - the model name is optional ledger context
                pass
            guard.refuse(refusal.status, refusal.code, refusal.message, requested_model=model,
                         endpoint="embeddings", extra=refusal.extra)
            self._send(refusal.status, _error_body(refusal.code, refusal.message))
            return
        try:
            response = guard.open_upstream(prep)
        except urllib.error.HTTPError as error:
            payload = error.read() if error.fp is not None else b""
            guard.finish(prep, outcome="upstream_error", http_status=error.code, usage=None)
            self._send(error.code, payload or _error_body("upstream_error", f"upstream HTTP {error.code}"))
            return
        except Exception as error:  # noqa: BLE001 - transport failures become 502
            guard.finish(prep, outcome="transport_error", http_status=502, usage=None)
            self._send(502, _error_body("upstream_transport", f"upstream transport error: {type(error).__name__}"))
            return
        with response:
            payload = response.read()
            usage = meta = None
            try:
                parsed = json.loads(payload)
                usage = parsed.get("usage")
                meta = _response_meta(parsed)
            except Exception:  # noqa: BLE001 - unparseable body counts as missing usage
                pass
            guard.finish(prep, outcome="ok", http_status=response.status, usage=usage, response_meta=meta)
            self._send(response.status, payload)

    def _embeddings(self, raw: bytes) -> None:
        guard = self.guard
        cfg = guard.config
        if cfg.upstream == "openai":
            self._exact_embeddings(raw)
            return
        if cfg.embeddings_base_url is None:
            message = "DeepSeek has no embeddings endpoint; declare a local embedder in the stage config"
            guard.refuse(400, "embeddings_unavailable", message, endpoint="embeddings")
            self._send(400, _error_body("embeddings_unavailable", message))
            return
        if guard.halted:
            guard.refuse(402, "guard_halted", "stage budget guard halted", endpoint="embeddings")
            self._send(402, _error_body("guard_halted", f"stage budget guard halted: {guard.halt_reason}"))
            return
        try:
            body = json.loads(raw)
            requested = str(body.get("model") or "")
            inputs = body.get("input")
            count = len(inputs) if isinstance(inputs, list) else 1
            body["model"] = cfg.embeddings_model
        except Exception:  # noqa: BLE001
            guard.refuse(400, "invalid_json", "request body is not JSON", endpoint="embeddings")
            self._send(400, _error_body("invalid_json", "request body is not JSON"))
            return
        started = time.monotonic()
        request = urllib.request.Request(
            cfg.embeddings_base_url.rstrip("/") + "/embeddings",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with guard._local_opener.open(request, timeout=cfg.request_timeout_s) as response:
                payload = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            payload, status = (error.read() if error.fp is not None else b""), error.code
            guard.record_embeddings(outcome="upstream_error", http_status=status, usage=None,
                                    inputs=count, requested_model=requested, started=started)
            self._send(status, payload or _error_body("upstream_error", f"upstream HTTP {status}"))
            return
        except Exception as error:  # noqa: BLE001
            guard.record_embeddings(outcome="transport_error", http_status=502, usage=None,
                                    inputs=count, requested_model=requested, started=started)
            self._send(502, _error_body("upstream_transport", f"upstream transport error: {type(error).__name__}"))
            return
        usage = None
        try:
            parsed = json.loads(payload)
            parsed["model"] = requested or parsed.get("model")
            usage = parsed.get("usage")
            payload = json.dumps(parsed).encode("utf-8")
        except Exception:  # noqa: BLE001
            pass
        guard.record_embeddings(outcome="ok", http_status=status, usage=usage,
                                inputs=count, requested_model=requested, started=started)
        self._send(status, payload)


# ---------------------------------------------------------------------------
# 3. Stage runner
# ---------------------------------------------------------------------------

STAGE_KEYS = {
    "description", "argv", "cap_usd", "cap_tokens", "cap_requests", "model_aliases",
    "request_model", "max_tokens_default", "max_tokens_ceiling", "timeout_seconds", "env",
    "venv", "local_embeddings", "paid_allowed", "dry_run_allowed", "dry_run_cap_requests",
    "estimate", "compares_to", "fidelity", "request_timeout_seconds",
    # Added with the provider_stages section (the schema stays auditor-adapter-stages/v1).
    "provider", "models", "blocked",
}

# Runner options that would silently become adapter arguments if written after "--"
# (argparse REMAINDER).  "--plan-only" there starts a real run; the "--cap-*" and
# "--lab-env" options there would not limit or route anything.  run-stage refuses them
# after "--" before it reads a key or starts a guard.
RUNNER_ONLY_OPTIONS: tuple[str, ...] = (
    "--plan-only", "--cap-usd", "--cap-tokens", "--cap-requests", "--lab-env", "--out-root",
    "--dry-run-ollama", "--ollama-url", "--ollama-model", "--grace-seconds", "--timeout-seconds",
    "--label", "--set",
)
# Abbreviations argparse would accept for these before "--" (and some adapters accept
# for their own --plan-only) are refused too.
_ABBREVIATED_RUNNER_OPTIONS: tuple[str, ...] = ("--plan-only", "--dry-run-ollama")


def misplaced_runner_options(extra_args: Iterable[str]) -> list[str]:
    """Runner options found among the arguments meant for the adapter (after "--")."""
    found: list[str] = []
    for token in extra_args:
        if not isinstance(token, str) or not token.startswith("--") or token == "--":
            continue
        name = token.split("=", 1)[0]
        if name in RUNNER_ONLY_OPTIONS or (
            len(name) >= 6 and any(option.startswith(name) for option in _ABBREVIATED_RUNNER_OPTIONS)
        ):
            found.append(name)
    return found


# A live run-stage writes a lock file next to this module (common/) and removes it
# when the child has ended, so anyone about to edit packages/auditor-adapters can see
# that a run is in flight.  Lock files are excluded from the receipts' git state.
RUN_LOCK_PREFIX = ".run-stage-"
RUN_LOCK_SUFFIX = ".lock"
_RUN_LOCK_STATUS = re.compile(r"(^|/)common/\.run-stage-[^/]*\.lock$")
# Files hashed for the launch/end code snapshot: common/ and the artifact's adapter dir.
_SNAPSHOT_SKIP_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}


def _validate_provider(merged: dict[str, Any], section: str, stage: str) -> None:
    """Provider rules of a merged stage.

    Stages under "stages" are DeepSeek (``provider`` absent or "deepseek").  Stages
    under "provider_stages" must name one non-DeepSeek provider explicitly.
    """
    provider = merged.get("provider", "deepseek")
    if not isinstance(provider, str) or provider not in PAID_PROVIDERS:
        raise RouteError(f"stage {stage!r}: provider must be exactly one of {list(PAID_PROVIDERS)}")
    blocked = merged.get("blocked")
    if blocked is not None and not (isinstance(blocked, str) and blocked.strip()):
        raise RouteError(f"stage {stage!r}: blocked must be a non-empty reason string")
    if section == "stages":
        if "blocked" in merged:
            # Runners from before the provider_stages change ignore 'blocked' and would
            # run the stage.  Both old and new runners honour paid_allowed/dry_run_allowed.
            raise RouteError(f"stage {stage!r}: 'blocked' is only for '{PROVIDER_STAGES_SECTION}'; older runners "
                             "ignore it, so block a DeepSeek stage with paid_allowed false and dry_run_allowed false")
        if provider != "deepseek":
            raise RouteError(f"stage {stage!r}: a {provider} stage belongs under '{PROVIDER_STAGES_SECTION}', "
                             "never under 'stages' (older runners would run it as DeepSeek)")
        if "models" in merged:
            raise RouteError(f"stage {stage!r}: 'models' is for exact-model providers; DeepSeek uses request_model "
                             "and model_aliases")
        return
    if provider == "deepseek" or "provider" not in merged:
        raise RouteError(f"stage {stage!r}: stages under '{PROVIDER_STAGES_SECTION}' must name a non-DeepSeek provider")
    models = merged.get("models")
    if (not isinstance(models, list) or not models or not all(isinstance(m, str) and m for m in models)
            or len(set(models)) != len(models)):
        raise RouteError(f"stage {stage!r}: a {provider} stage needs 'models', a non-empty list of distinct exact ids")
    if merged.get("request_model") not in models:
        raise RouteError(f"stage {stage!r}: request_model must be one of its models {models}")
    if merged.get("model_aliases"):
        raise RouteError(f"stage {stage!r}: {provider} never rewrites the model; model_aliases must be empty")
    if merged.get("local_embeddings") is not None:
        raise RouteError(f"stage {stage!r}: {provider} stages use the provider's embeddings, not local_embeddings")
    if merged.get("dry_run_allowed"):
        raise RouteError(f"stage {stage!r}: {provider} stages have no Ollama dry run; set dry_run_allowed false "
                         "and test against a loopback fake")
    if not blocked:
        specs = provider_models(load_providers(), provider, models)
        if specs[merged["request_model"]].kind != "chat":
            raise RouteError(f"stage {stage!r}: request_model must be a chat model")


def load_stage(config_path: Path, stage: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (merged stage dict, whole config) after validation."""
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RouteError(f"stage config not found: {config_path}") from None
    if config.get("schema") != SCHEMA_STAGES:
        raise RouteError(f"{config_path} schema must be {SCHEMA_STAGES}")
    stages = config.get("stages") or {}
    provider_stages = config.get(PROVIDER_STAGES_SECTION) or {}
    if not isinstance(provider_stages, dict):
        raise RouteError(f"{config_path}: '{PROVIDER_STAGES_SECTION}' must be an object")
    overlap = sorted(set(stages) & set(provider_stages))
    if overlap:
        raise RouteError(f"{config_path}: stage names {overlap} appear in both 'stages' and '{PROVIDER_STAGES_SECTION}'")
    if stage in stages:
        section, raw_stage = "stages", stages[stage]
    elif stage in provider_stages:
        section, raw_stage = PROVIDER_STAGES_SECTION, provider_stages[stage]
    else:
        known = sorted(stages) + sorted(provider_stages)
        raise RouteError(f"stage {stage!r} not in {config_path}; known: {known}")
    merged = {**(config.get("defaults") or {}), **raw_stage}
    merged["env"] = {**((config.get("defaults") or {}).get("env") or {}), **(raw_stage.get("env") or {})}
    unknown = sorted(set(merged) - STAGE_KEYS)
    # Other keys are adapter metadata and are ignored, except likely typos of
    # safety-relevant keys, which are refused.
    suspicious = [k for k in unknown if re.match(
        r"(cap_|max_tokens|model|request_model|local_embed|venv|argv|env$|timeout|paid|dry_run|provider|block)", k)]
    if suspicious:
        raise RouteError(f"unrecognised safety-relevant stage keys {suspicious} in {config_path}; "
                         f"known keys: {sorted(STAGE_KEYS)}")
    merged["_ignored_keys"] = unknown
    argv = merged.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise RouteError("stage argv must be a non-empty list of strings")
    for key in ("cap_usd", "cap_tokens"):
        if not isinstance(merged.get(key), (int, float)) or merged[key] <= 0:
            raise RouteError(f"stage {stage!r} needs a positive {key} ceiling")
    for name, value in merged["env"].items():
        if not isinstance(value, str):
            raise RouteError(f"env {name} must be a string")
        upper = name.upper()
        if upper.endswith(STRIPPED_SUFFIXES) and value != "{guard_token}":
            raise RouteError(f"env {name} looks like a credential; only '{{guard_token}}' is allowed")
        if upper.endswith(("_BASE_URL", "_API_BASE", "_ENDPOINT", "_URL", "_HOST")) and not (
            value == "{guard_base_url}" or _is_loopback(value)
        ):
            raise RouteError(f"env {name} must be '{{guard_base_url}}' or a loopback URL")
    embeddings = merged.get("local_embeddings")
    if embeddings is not None:
        if not isinstance(embeddings, dict) or not _is_loopback(str(embeddings.get("base_url", ""))) or not embeddings.get("model"):
            raise RouteError("local_embeddings needs a loopback base_url and a model")
    _validate_provider(merged, section, stage)
    return merged, config


def _substitute(text: str, values: Mapping[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            raise RouteError(f"unresolved placeholder {{{name}}}; pass --set {name}=... or the matching option")
        return values[name]

    return _PLACEHOLDER.sub(replace, text)


def _repo_root() -> Path:
    try:
        out = subprocess.run(
            ["git", "-C", str(COMMON_DIR), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=30, check=True,
        ).stdout.strip()
        return Path(out).resolve()
    except Exception:  # noqa: BLE001
        return COMMON_DIR.parents[2]


def _git_state(repo: Path) -> dict[str, Any]:
    def git(*args: str) -> str:
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=30).stdout.strip()

    try:
        status = git("status", "--porcelain", "--", "packages/auditor-adapters")
        # Live run-stage lock files (common/.run-stage-*.lock) are not code changes.
        lines = [line for line in status.splitlines() if not _RUN_LOCK_STATUS.search(line.strip().strip('"'))]
        return {
            "commit": git("rev-parse", "HEAD") or None,
            "adapters_dirty": bool(lines),
            "adapters_status": lines[:200],
        }
    except Exception as error:  # noqa: BLE001
        return {"commit": None, "error": type(error).__name__}


def _sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


# The guard bytes this process actually loaded (receipts also hash the file at the end).
GUARD_SHA256_AT_IMPORT = _sha256_file(Path(__file__).resolve())


def _is_run_lock(path: Path) -> bool:
    return path.name.startswith(RUN_LOCK_PREFIX) and path.name.endswith(RUN_LOCK_SUFFIX)


def _tree_files(roots: Iterable[Path]) -> dict[str, str]:
    """sha256 of every file under ``roots`` (paths relative to the adapters dir), caches and locks skipped."""
    files: dict[str, str] = {}
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            try:
                relative = path.relative_to(ADAPTERS_DIR)
            except ValueError:
                relative = path
            if (not path.is_file() or any(part in _SNAPSHOT_SKIP_DIRS for part in relative.parts)
                    or path.suffix in (".pyc", ".pyo") or _is_run_lock(path)):
                continue
            files[relative.as_posix()] = _sha256_file(path) or "unreadable"
    return files


def _code_snapshot(repo: Path, config_path: Path, artifact: str, exact: bool) -> tuple[dict[str, Any], dict[str, str]]:
    """Hashes of the code a run depends on, taken before the child starts and again after it ends."""
    roots = [COMMON_DIR]
    adapter_dir = ADAPTERS_DIR / artifact
    if adapter_dir.resolve() != COMMON_DIR.resolve():
        roots.append(adapter_dir)
    files = _tree_files(roots)
    snapshot: dict[str, Any] = {
        "taken_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git": _git_state(repo),
        "deepseek_route_sha256": _sha256_file(Path(__file__)),
        "stage_config_sha256": _sha256_file(config_path),
        "adapter_tree_sha256": hashlib.sha256(
            "".join(f"{name}\t{digest}\n" for name, digest in sorted(files.items())).encode("utf-8")).hexdigest(),
        "adapter_tree_files": len(files),
    }
    if exact:
        snapshot["providers_sha256"] = _sha256_file(PROVIDERS_PATH)
    return snapshot, files


def _snapshot_changes(launch: Mapping[str, Any], end: Mapping[str, Any], launch_files: Mapping[str, str],
                      end_files: Mapping[str, str]) -> tuple[list[str], list[str], bool]:
    """(changed keys that bear on this run, changed files of common/ and the adapter, git status changed).

    A change elsewhere under packages/auditor-adapters (another adapter's files) only
    shows up in the git status flag, which is reported separately.
    """
    keys = ("deepseek_route_sha256", "stage_config_sha256", "adapter_tree_sha256", "providers_sha256")
    changed = [key for key in keys if launch.get(key) != end.get(key)]
    launch_git, end_git = launch.get("git") or {}, end.get("git") or {}
    if launch_git.get("commit") != end_git.get("commit"):
        changed.append("git.commit")
    status_changed = any(launch_git.get(key) != end_git.get(key) for key in ("adapters_dirty", "adapters_status"))
    files = sorted(name for name in set(launch_files) | set(end_files) if launch_files.get(name) != end_files.get(name))
    return changed, files[:100], status_changed


def _live_run_locks() -> list[str]:
    try:
        return sorted(path.name for path in COMMON_DIR.iterdir() if _is_run_lock(path))
    except OSError:
        return []


def _write_run_lock(record: Mapping[str, Any]) -> Path | None:
    path = COMMON_DIR / f"{RUN_LOCK_PREFIX}{os.getpid()}-{uuid.uuid4().hex[:8]}{RUN_LOCK_SUFFIX}"
    try:
        path.write_text(json.dumps(dict(record), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        return None
    return path


def _remove_run_lock(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except OSError:
        pass


def _inside_git_worktree(directory: Path) -> bool:
    try:
        out = subprocess.run(["git", "-C", str(directory), "rev-parse", "--is-inside-work-tree"],
                             capture_output=True, text=True, timeout=30)
    except Exception:  # noqa: BLE001 - no git: only the repository check below applies
        return False
    return out.returncode == 0 and out.stdout.strip() == "true"


def check_provider_key_file(path: str | os.PathLike[str], key_env: str, repo: Path | None = None) -> None:
    """Refuse a key file for an exact-model provider that other code could load unmetered.

    The lab ``.env`` is loaded into the process environment by the lab runner and by the
    vendored AgentDojo scripts (``load_dotenv``), and ``OPENAI_API_KEY`` is the default
    credential of the OpenAI SDK and LangChain.  So the key must live in a dedicated file
    that is not named ``.env`` and is outside every git work tree.  Existence only; the
    file is not read here.
    """
    resolved = Path(path).resolve()
    if resolved.name.lower() == ".env":
        raise RouteError(f"{key_env} must be in a dedicated key file that is not named .env (got {resolved}); "
                         "see RUN-PLAN-OPENAI.md precondition P1")
    root = _repo_root() if repo is None else repo
    if _is_within(resolved, root) or _inside_git_worktree(resolved.parent):
        raise RouteError(f"{key_env} key file {resolved} is inside a git work tree; keep it in a dedicated file "
                         "outside every repository (RUN-PLAN-OPENAI.md precondition P1)")


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def find_dotenv_on_path(directory: Path) -> list[str]:
    """Existence check only: .env files in ``directory`` or any ancestor."""
    hits = []
    for folder in (directory.resolve(), *directory.resolve().parents):
        candidate = folder / ".env"
        if candidate.exists():
            hits.append(str(candidate))
    return hits


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, timeout=60)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except Exception:  # noqa: BLE001
        proc.kill()
    try:
        proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()


@dataclass
class StageRequest:
    artifact: str
    stage: str
    cap_usd: Decimal
    cap_tokens: int
    out_root: Path
    dry_run_ollama: bool = False
    cap_requests: int | None = None
    lab_env: Path | None = None
    artifact_root: Path | None = None
    config_path: Path | None = None
    ollama_url: str = OLLAMA_DEFAULT_URL
    ollama_model: str = OLLAMA_DEFAULT_MODEL
    extra_values: dict[str, str] = field(default_factory=dict)
    extra_args: list[str] = field(default_factory=list)
    timeout_seconds: float | None = None
    grace_seconds: float = 5.0
    plan_only: bool = False
    label: str | None = None
    # Test hook: a loopback double that stands in for api.deepseek.com.
    deepseek_url_override: str | None = None
    # Test hook for exact-model providers: a loopback double for api.openai.com.
    upstream_url_override: str | None = None


def run_stage(req: StageRequest, base_env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Run one stage under the guard and return the receipt (also written to disk)."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", req.artifact):
        raise RouteError("artifact key must be lowercase [a-z0-9_-]")
    misplaced = misplaced_runner_options(req.extra_args)
    if misplaced:
        raise RouteError(f"runner option(s) {misplaced} appear after '--', where they would be passed to the adapter "
                         "instead of the runner (after '--', --plan-only would start a real run); put every runner "
                         "option before '--'. Nothing was started and no key was read.")
    config_path = req.config_path or (ADAPTERS_DIR / req.artifact / "stages.json")
    stage, _config = load_stage(config_path, req.stage)
    provider = str(stage.get("provider", "deepseek"))
    exact = provider != "deepseek"  # exact-model provider (openai): no rewrite, priced allowlist
    mode = "ollama-dry-run" if req.dry_run_ollama else provider
    if stage.get("blocked") and not req.plan_only:
        raise RouteError(f"stage {req.stage} is blocked: {stage['blocked']}")
    if exact and req.dry_run_ollama:
        raise RouteError(f"stage {req.stage} is a {provider} stage; there is no Ollama dry run for it")
    if exact and req.deepseek_url_override:
        raise RouteError("deepseek_url_override cannot be used with a non-DeepSeek stage")
    if req.dry_run_ollama and not stage.get("dry_run_allowed", True):
        raise RouteError(f"stage {req.stage} does not allow an Ollama dry run")
    if not req.dry_run_ollama and not stage.get("paid_allowed", True):
        raise RouteError(f"stage {req.stage} is dry-run only")
    if req.cap_usd <= 0 or req.cap_tokens <= 0:
        raise RouteError("--cap-usd and --cap-tokens must be positive")
    if req.cap_usd > Decimal(str(stage["cap_usd"])):
        raise RouteError(f"--cap-usd {req.cap_usd} exceeds the stage ceiling {stage['cap_usd']}")
    if req.cap_tokens > int(stage["cap_tokens"]):
        raise RouteError(f"--cap-tokens {req.cap_tokens} exceeds the stage ceiling {stage['cap_tokens']}")
    cap_requests = req.cap_requests
    ceiling_requests = stage.get("dry_run_cap_requests") if req.dry_run_ollama else stage.get("cap_requests")
    if ceiling_requests is not None:
        cap_requests = min(cap_requests or int(ceiling_requests), int(ceiling_requests))
    if req.dry_run_ollama and cap_requests is None:
        cap_requests = DRY_RUN_DEFAULT_CAP_REQUESTS
    if req.dry_run_ollama and not _is_loopback(req.ollama_url):
        raise RouteError("--ollama-url must be a loopback URL")

    repo = _repo_root()
    out_root = req.out_root.resolve()
    if _is_within(out_root, repo):
        raise RouteError(f"--out-root {out_root} is inside the code repository {repo}; use the results checkout or the artifact smoke dir")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_name = f"{stamp}-{mode}" + (f"-{req.label}" if req.label else "")
    out_dir = out_root / req.artifact / req.stage / run_name
    scratch = out_dir / "cwd"

    artifact_root = req.artifact_root
    if artifact_root is None and os.environ.get("AUDITOR_ARTIFACTS_ROOT"):
        artifact_root = Path(os.environ["AUDITOR_ARTIFACTS_ROOT"]) / req.artifact
    venv = stage.get("venv", ".venv")
    values: dict[str, str] = {
        "python": sys.executable,
        "common_dir": str(COMMON_DIR),
        "adapter_dir": str(ADAPTERS_DIR / req.artifact),
        "out_dir": str(out_dir),
        "cwd": str(scratch),
        "artifact": req.artifact,
        "stage": req.stage,
        "model": str(stage.get("request_model", DEEPSEEK_MODEL)),
        "mode": mode,
        "guard_base_url": "{guard_base_url}",
        "guard_token": "{guard_token}",
    }
    if artifact_root is not None:
        root = Path(artifact_root).resolve()
        python = root / venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        values["artifact_root"] = str(root)
        values["artifact_python"] = str(python)
    for key, value in req.extra_values.items():
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or key in ("guard_token", "guard_base_url"):
            raise RouteError(f"invalid --set name {key!r}")
        values.setdefault(key, value)
    argv = [_substitute(item, values) for item in stage["argv"]] + list(req.extra_args)
    env_extra = {name: _substitute(value, values) for name, value in stage["env"].items()}
    plan = {
        "artifact": req.artifact,
        "stage": req.stage,
        "mode": mode,
        "argv": argv,
        "env_names": sorted(env_extra),
        "cap_usd": str(req.cap_usd),
        "cap_tokens": req.cap_tokens,
        "cap_requests": cap_requests,
        "out_dir": str(out_dir),
        "config": str(config_path),
        "ignored_keys": stage.get("_ignored_keys", []),
    }
    if exact:
        plan["provider"] = provider
        plan["models"] = list(stage["models"])
    if stage.get("blocked"):
        plan["blocked"] = stage["blocked"]
    if req.plan_only:
        return {"plan": plan}
    if "artifact_python" in values and not Path(values["artifact_python"]).is_file() and "{artifact_python}" in json.dumps(stage["argv"]):
        raise RouteError(f"artifact venv python not found: {values['artifact_python']}")

    providers: dict[str, Any] | None = None
    specs: dict[str, ModelSpec] = {}
    if exact:
        providers = load_providers()
        specs = provider_models(providers, provider, stage["models"])
        if req.upstream_url_override and not _is_loopback(req.upstream_url_override):
            raise RouteError("upstream_url_override is a loopback test hook only")
    api_key: str | None = None
    if not req.dry_run_ollama:
        if req.lab_env is None:
            raise RouteError("a paid stage needs --lab-env (or AUDITOR_LAB_ENV) pointing at the lab .env")
        if exact:
            assert providers is not None
            key_env = providers["providers"][provider]["key_env"]
            check_provider_key_file(req.lab_env, key_env, repo)
            api_key = read_provider_key(req.lab_env, key_env)
        else:
            api_key = load_deepseek_env(req.lab_env, base_env={})["OPENAI_API_KEY"]

    scratch.mkdir(parents=True, exist_ok=False)
    dotenvs = find_dotenv_on_path(scratch)
    if dotenvs:
        raise RouteError(f"refusing to run: .env found on the scratch cwd path: {dotenvs}")

    embeddings = stage.get("local_embeddings") or {}
    if exact:
        gcfg = GuardConfig(
            stage_id=f"{req.artifact}/{req.stage}/{run_name}",
            ledger_path=out_dir / "ledger.jsonl",
            cap_usd=req.cap_usd,
            cap_tokens=req.cap_tokens,
            cap_requests=cap_requests,
            upstream=provider,
            upstream_base_url=req.upstream_url_override or OPENAI_BASE_URL,
            upstream_model="",
            request_model=str(stage["request_model"]),
            model_aliases=(),
            api_key=api_key,
            max_tokens_default=int(stage.get("max_tokens_default", 2048)),
            max_tokens_ceiling=int(stage.get("max_tokens_ceiling", 4096)),
            request_timeout_s=float(stage.get("request_timeout_seconds", 120.0)),
            models=specs,
        )
    else:
        gcfg = GuardConfig(
            stage_id=f"{req.artifact}/{req.stage}/{run_name}",
            ledger_path=out_dir / "ledger.jsonl",
            cap_usd=req.cap_usd,
            cap_tokens=req.cap_tokens,
            cap_requests=cap_requests,
            upstream="ollama" if req.dry_run_ollama else "deepseek",
            upstream_base_url=req.ollama_url if req.dry_run_ollama else (req.deepseek_url_override or DEEPSEEK_BASE_URL),
            upstream_model=req.ollama_model if req.dry_run_ollama else DEEPSEEK_MODEL,
            request_model=str(stage.get("request_model", DEEPSEEK_MODEL)),
            model_aliases=tuple(stage.get("model_aliases") or ()),
            api_key=api_key,
            max_tokens_default=int(stage.get("max_tokens_default", 2048)),
            max_tokens_ceiling=int(stage.get("max_tokens_ceiling", 4096)),
            request_timeout_s=float(stage.get("request_timeout_seconds", 120.0)),
            embeddings_base_url=embeddings.get("base_url"),
            embeddings_model=embeddings.get("model"),
        )
    if req.deepseek_url_override and not _is_loopback(req.deepseek_url_override):
        raise RouteError("deepseek_url_override is a loopback test hook only")
    guard = BudgetGuard(gcfg)
    del api_key
    started_at = datetime.now(timezone.utc)
    status, exit_code, child_rc = "completed", 0, None
    timeout = float(req.timeout_seconds or stage.get("timeout_seconds", 3600))
    stdout_path, stderr_path = out_dir / "child_stdout.txt", out_dir / "child_stderr.txt"
    launch_snapshot: dict[str, Any] | None = None
    launch_files: dict[str, str] = {}
    other_locks: list[str] = []
    lock_path: Path | None = None
    guard_url = guard.start()
    try:
        values["guard_base_url"] = guard_url
        token = gcfg.client_token
        argv = [item.replace("{guard_base_url}", guard_url).replace("{guard_token}", token) for item in argv]
        env_resolved = {
            name: value.replace("{guard_base_url}", guard_url).replace("{guard_token}", token)
            for name, value in env_extra.items()
        }
        child_env = guarded_child_env(os.environ if base_env is None else base_env, guard_url, token)
        child_env.update(env_resolved)
        child_env.update(
            {
                "AUDITOR_ARTIFACT": req.artifact,
                "AUDITOR_STAGE": req.stage,
                "AUDITOR_MODE": mode,
                "AUDITOR_OUT_DIR": str(out_dir),
                "AUDITOR_REQUEST_MODEL": gcfg.request_model,
                "AUDITOR_BACKBONE": "deepseek-flash" if not req.dry_run_ollama else f"ollama:{gcfg.upstream_model}",
            }
        )
        if exact:
            # Only exact-model stages add these, so a DeepSeek child env is unchanged.
            child_env.update(
                {
                    "AUDITOR_PROVIDER": provider,
                    "AUDITOR_MODELS": ",".join(gcfg.models),
                    "AUDITOR_BACKBONE": f"{provider}:" + ",".join(gcfg.models),
                }
            )
        popen_kwargs: dict[str, Any] = {}
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        # What is about to run, hashed before the child starts; compared again at the end.
        launch_snapshot, launch_files = _code_snapshot(repo, config_path, req.artifact, exact)
        other_locks = _live_run_locks()
        if other_locks:
            print(f"deepseek_route: note: other run-stage locks in {COMMON_DIR}: {other_locks}; "
                  "do not edit packages/auditor-adapters while a run is live", file=sys.stderr)
        lock_path = _write_run_lock({
            "pid": os.getpid(), "artifact": req.artifact, "stage": req.stage, "mode": mode,
            "out_dir": str(out_dir), "started_at": started_at.isoformat(timespec="seconds"),
            "note": "a run-stage is live; do not edit packages/auditor-adapters until this file is gone",
        })
        with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
            try:
                proc = subprocess.Popen(argv, cwd=scratch, env=child_env, stdin=subprocess.DEVNULL,
                                        stdout=out, stderr=err, **popen_kwargs)
            except OSError as error:
                status = "launch_failed"
                err.write(f"launch failed: {type(error).__name__}: {error}".encode("utf-8", "replace"))
                proc = None
            deadline = time.monotonic() + timeout
            halt_seen: float | None = None
            while proc is not None:
                child_rc = proc.poll()
                if child_rc is not None:
                    break
                now = time.monotonic()
                if guard.stop_child:
                    halt_seen = halt_seen or now
                    if now - halt_seen >= req.grace_seconds:
                        _kill_tree(proc)
                        child_rc = proc.returncode
                        break
                if now > deadline:
                    status = "timeout"
                    _kill_tree(proc)
                    child_rc = proc.returncode
                    break
                time.sleep(0.2)
    finally:
        guard.stop()
        _remove_run_lock(lock_path)
    end_snapshot, end_files = _code_snapshot(repo, config_path, req.artifact, exact)
    changed, files_changed, status_changed = _snapshot_changes(launch_snapshot or {}, end_snapshot, launch_files,
                                                               end_files)
    if launch_snapshot is not None and GUARD_SHA256_AT_IMPORT != launch_snapshot.get("deepseek_route_sha256"):
        changed.insert(0, "deepseek_route_sha256_at_import")
    summary = guard.summary()
    if status not in ("timeout", "launch_failed"):
        if guard.stop_child:
            status = "halted"
        elif child_rc != 0:
            status = "child_failed"
    exit_code = {"completed": 0, "halted": 3, "timeout": 4, "launch_failed": 5}.get(status, child_rc or 1)
    finished_at = datetime.now(timezone.utc)
    redacted_argv = [item.replace(gcfg.client_token, "[GUARD_TOKEN]") for item in argv]
    ledger_lines = 0
    if gcfg.ledger_path.exists():
        with gcfg.ledger_path.open("rb") as handle:
            ledger_lines = sum(1 for _ in handle)
    receipt = {
        "schema": SCHEMA_RECEIPT,
        "artifact": req.artifact,
        "stage": req.stage,
        "run": run_name,
        "mode": mode,
        "fidelity_label": "backbone-substituted (deepseek-flash)" if not req.dry_run_ollama else "plumbing dry run only (not evidence)",
        "status": status,
        "exit_code": exit_code,
        "child_returncode": child_rc,
        "started_at": started_at.isoformat(timespec="seconds"),
        "finished_at": finished_at.isoformat(timespec="seconds"),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 1),
        "argv": redacted_argv,
        "cwd": str(scratch),
        "child_env_added": sorted([*env_resolved, "OPENAI_BASE_URL", "OPENAI_API_KEY(guard token)"]),
        "child_env_stripped": stripped_names(os.environ if base_env is None else base_env),
        "caps": {
            "cap_usd": str(req.cap_usd),
            "cap_tokens": req.cap_tokens,
            "cap_requests": cap_requests,
            "stage_ceiling_usd": stage["cap_usd"],
            "stage_ceiling_tokens": stage["cap_tokens"],
        },
        "guard": summary,
        "price_snapshot": PRICE_SNAPSHOT,
        "ledger_sha256": _sha256_file(gcfg.ledger_path),
        "ledger_lines": ledger_lines,
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
        "stage_estimate": stage.get("estimate"),
        "stage_ignored_keys": stage.get("_ignored_keys", []),
        "compares_to": stage.get("compares_to"),
        # The top-level hashes are taken when the receipt is written (as before).  "launch"
        # holds the same hashes taken before the child started; if anything differs,
        # code_changed_during_run is true and the end-time hashes describe files that did
        # not run (use "launch" and deepseek_route_sha256_at_import instead).
        "code": {
            **end_snapshot["git"],
            "deepseek_route_sha256": end_snapshot["deepseek_route_sha256"],
            "stage_config": str(config_path),
            "stage_config_sha256": end_snapshot["stage_config_sha256"],
            "deepseek_route_sha256_at_import": GUARD_SHA256_AT_IMPORT,
            "launch": launch_snapshot,
            "end_adapter_tree_sha256": end_snapshot["adapter_tree_sha256"],
            "code_changed_during_run": bool(changed),
            "changed_during_run": changed,
            "files_changed_during_run": files_changed,
            "adapters_status_changed_during_run": status_changed,
            "run_lock": str(lock_path) if lock_path is not None else None,
            "other_runs_live_at_launch": other_locks,
        },
        "runner": {"python": sys.executable, "version": platform.python_version(), "platform": platform.platform()},
        "lab_env": str(req.lab_env) if req.lab_env and not req.dry_run_ollama else None,
    }
    if exact:
        assert providers is not None
        receipt["child_env_added"] = sorted([*receipt["child_env_added"], "AUDITOR_PROVIDER", "AUDITOR_MODELS"])
        receipt["provider"] = provider
        receipt["fidelity_label"] = f"published-backbone fidelity check ({provider}: {', '.join(gcfg.models)})"
        receipt["price_snapshot"] = price_snapshot_for(providers, provider, gcfg.models)
        receipt["code"]["providers_json"] = str(PROVIDERS_PATH)
        receipt["code"]["providers_sha256"] = _sha256_file(PROVIDERS_PATH)
    receipt_path = out_dir / "receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    receipt["receipt_path"] = str(receipt_path)
    return receipt


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _decimal(text: str) -> Decimal:
    try:
        value = Decimal(text)
    except Exception:  # noqa: BLE001
        raise argparse.ArgumentTypeError(f"not a number: {text}") from None
    if not value.is_finite() or value <= 0:
        raise argparse.ArgumentTypeError("must be a positive number")
    return value


def exact_serve_config(args: argparse.Namespace) -> GuardConfig:
    """Guard config for ``serve --provider openai``, bounded by a tracked provider stage.

    The standalone guard honours the same stage rules as run-stage: a blocked stage is
    refused, the caps may not exceed the stage ceilings, the request cap and the output
    limits come from the stage, and the models are the stage's (or a subset of them).
    """
    provider = args.provider
    if args.dry_run_ollama or args.model_alias:
        raise RouteError(f"--provider {provider} has no Ollama dry run and no model aliases")
    if not args.artifact or not args.stage:
        raise RouteError(f"--provider {provider} needs --artifact and --stage: the standalone guard is bounded by a "
                         "provider stage (its blocked flag, cap ceilings, output limits and models)")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", args.artifact):
        raise RouteError("artifact key must be lowercase [a-z0-9_-]")
    config_path = args.config or (ADAPTERS_DIR / args.artifact / "stages.json")
    stage, _config = load_stage(config_path, args.stage)
    if stage.get("provider", "deepseek") != provider:
        raise RouteError(f"stage {args.stage} is not a {provider} stage")
    if stage.get("blocked"):
        raise RouteError(f"stage {args.stage} is blocked: {stage['blocked']}")
    if not stage.get("paid_allowed", True):
        raise RouteError(f"stage {args.stage} does not allow paid requests")
    if args.cap_tokens <= 0:
        raise RouteError("--cap-tokens must be positive")
    if args.cap_usd > Decimal(str(stage["cap_usd"])):
        raise RouteError(f"--cap-usd {args.cap_usd} exceeds the stage ceiling {stage['cap_usd']}")
    if args.cap_tokens > int(stage["cap_tokens"]):
        raise RouteError(f"--cap-tokens {args.cap_tokens} exceeds the stage ceiling {stage['cap_tokens']}")
    cap_requests = args.cap_requests
    if stage.get("cap_requests") is not None:
        cap_requests = min(cap_requests or int(stage["cap_requests"]), int(stage["cap_requests"]))
    models = list(args.model) or list(stage["models"])
    outside = [model for model in models if model not in stage["models"]]
    if outside:
        raise RouteError(f"--model {outside} is not among the stage's models {stage['models']}")
    request_model = models[0] if args.model else str(stage["request_model"])
    if args.lab_env is None:
        raise RouteError("--lab-env is required")
    table = load_providers()
    specs = provider_models(table, provider, models)
    if specs[request_model].kind != "chat":
        raise RouteError("the request model (the first --model) must be a chat model")
    key_env = table["providers"][provider]["key_env"]
    check_provider_key_file(args.lab_env, key_env)
    return GuardConfig(
        stage_id=args.stage_id, ledger_path=args.ledger, cap_usd=args.cap_usd, cap_tokens=args.cap_tokens,
        cap_requests=cap_requests, upstream=provider, upstream_base_url=OPENAI_BASE_URL, upstream_model="",
        request_model=request_model, models=specs,
        max_tokens_default=int(stage.get("max_tokens_default", 2048)),
        max_tokens_ceiling=int(stage.get("max_tokens_ceiling", 4096)),
        request_timeout_s=float(stage.get("request_timeout_seconds", 120.0)),
        api_key=read_provider_key(args.lab_env, key_env),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="deepseek_route.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run-stage", help="run one adapter stage under the budget guard")
    run.add_argument("--artifact", required=True)
    run.add_argument("--stage", required=True)
    run.add_argument("--cap-usd", required=True, type=_decimal, help="hard USD cap for this run (<= stage ceiling)")
    run.add_argument("--cap-tokens", required=True, type=int, help="hard prompt+completion token cap (<= stage ceiling)")
    run.add_argument("--cap-requests", type=int, default=None)
    run.add_argument("--dry-run-ollama", action="store_true", help="forward to local Ollama; never reads the key")
    run.add_argument("--ollama-url", default=OLLAMA_DEFAULT_URL)
    run.add_argument("--ollama-model", default=OLLAMA_DEFAULT_MODEL)
    run.add_argument("--out-root", type=Path, default=os.environ.get("AUDITOR_OUT_ROOT"),
                     help="outside the code repo: results checkout or the artifact smoke dir (env AUDITOR_OUT_ROOT)")
    run.add_argument("--lab-env", type=Path, default=os.environ.get("AUDITOR_LAB_ENV"),
                     help="lab .env holding the stage provider's key, DEEPSEEK_API_KEY or OPENAI_API_KEY "
                          "(env AUDITOR_LAB_ENV); only that one line is read")
    run.add_argument("--artifact-root", type=Path, default=None,
                     help="artifact checkout (default $AUDITOR_ARTIFACTS_ROOT/<artifact>)")
    run.add_argument("--config", type=Path, default=None, help="stage config (default <adapters>/<artifact>/stages.json)")
    run.add_argument("--set", action="append", default=[], metavar="NAME=VALUE", help="extra placeholder value")
    run.add_argument("--timeout-seconds", type=float, default=None)
    run.add_argument("--grace-seconds", type=float, default=5.0)
    run.add_argument("--label", default=None)
    run.add_argument("--plan-only", action="store_true",
                     help="validate and print the resolved plan; no guard, no key (must come before --)")
    run.add_argument("extra", nargs=argparse.REMAINDER,
                     help="after --: appended to the stage argv; runner options there are refused")

    serve = sub.add_parser("serve", help="standalone guard for adapter development (Ctrl-C to stop)")
    serve.add_argument("--stage-id", required=True)
    serve.add_argument("--ledger", required=True, type=Path)
    serve.add_argument("--cap-usd", required=True, type=_decimal)
    serve.add_argument("--cap-tokens", required=True, type=int)
    serve.add_argument("--cap-requests", type=int, default=None)
    serve.add_argument("--model-alias", action="append", default=[])
    serve.add_argument("--provider", choices=list(PAID_PROVIDERS), default="deepseek")
    serve.add_argument("--artifact", default=None,
                       help="openai only (required): the artifact whose provider stage bounds this guard")
    serve.add_argument("--stage", default=None,
                       help="openai only (required): a provider stage; its blocked flag, caps and models apply")
    serve.add_argument("--config", type=Path, default=None, help="stage config (default <adapters>/<artifact>/stages.json)")
    serve.add_argument("--model", action="append", default=[],
                       help="openai only: narrow the stage's models to these exact ids (repeat; first is the request model)")
    serve.add_argument("--dry-run-ollama", action="store_true")
    serve.add_argument("--ollama-url", default=OLLAMA_DEFAULT_URL)
    serve.add_argument("--ollama-model", default=OLLAMA_DEFAULT_MODEL)
    serve.add_argument("--lab-env", type=Path, default=os.environ.get("AUDITOR_LAB_ENV"))
    serve.add_argument("--port", type=int, default=0)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "run-stage":
            if args.out_root is None:
                raise RouteError("--out-root (or AUDITOR_OUT_ROOT) is required")
            extra_values = {}
            for item in args.set:
                name, sep, value = item.partition("=")
                if not sep:
                    raise RouteError(f"--set needs NAME=VALUE, got {item!r}")
                extra_values[name] = value
            extra = list(args.extra)
            if extra and extra[0] == "--":
                extra = extra[1:]
            receipt = run_stage(
                StageRequest(
                    artifact=args.artifact, stage=args.stage, cap_usd=args.cap_usd, cap_tokens=args.cap_tokens,
                    out_root=Path(args.out_root), dry_run_ollama=args.dry_run_ollama, cap_requests=args.cap_requests,
                    lab_env=Path(args.lab_env) if args.lab_env else None, artifact_root=args.artifact_root,
                    config_path=args.config, ollama_url=args.ollama_url, ollama_model=args.ollama_model,
                    extra_values=extra_values, extra_args=extra, timeout_seconds=args.timeout_seconds,
                    grace_seconds=args.grace_seconds, plan_only=args.plan_only, label=args.label,
                )
            )
            if args.plan_only:
                print(json.dumps(receipt["plan"], indent=2))
                return 0
            guard = receipt["guard"]
            print(json.dumps({
                "status": receipt["status"], "exit_code": receipt["exit_code"],
                "requests": guard["requests_forwarded"], "refused": guard["requests_refused"],
                "tokens": guard["total_tokens"], "usd": guard["usd"], "halt_reason": guard["halt_reason"],
                "receipt": receipt["receipt_path"],
            }, indent=2))
            return int(receipt["exit_code"])
        if args.command == "serve" and args.provider != "deepseek":
            cfg = exact_serve_config(args)
        elif args.command == "serve":
            api_key = None
            if not args.dry_run_ollama:
                if args.lab_env is None:
                    raise RouteError("--lab-env is required unless --dry-run-ollama")
                api_key = read_deepseek_key(args.lab_env)
            cfg = GuardConfig(
                stage_id=args.stage_id, ledger_path=args.ledger, cap_usd=args.cap_usd, cap_tokens=args.cap_tokens,
                cap_requests=args.cap_requests, model_aliases=tuple(args.model_alias),
                upstream="ollama" if args.dry_run_ollama else "deepseek",
                upstream_base_url=args.ollama_url if args.dry_run_ollama else DEEPSEEK_BASE_URL,
                upstream_model=args.ollama_model if args.dry_run_ollama else DEEPSEEK_MODEL,
                api_key=api_key,
            )
        if args.command == "serve":
            guard = BudgetGuard(cfg)
            url = guard.start(args.port)
            print(json.dumps({"guard_base_url": url, "guard_token": cfg.client_token,
                              "note": "set OPENAI_BASE_URL and OPENAI_API_KEY to these in the child"}), flush=True)
            try:
                while not guard.halted:
                    time.sleep(0.5)
                print(json.dumps({"halted": guard.halt_reason}), flush=True)
            except KeyboardInterrupt:
                pass
            finally:
                guard.stop()
                print(json.dumps(guard.summary(), indent=2))
            return 0
    except RouteError as error:
        print(f"deepseek_route: {error}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
