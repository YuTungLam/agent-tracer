"""DeepSeek routing helpers for the released AttriGuard artifact.

Artifact: He et al., "AttriGuard", USENIX Security 2026, Zenodo DOI 10.5281/zenodo.20308739
(zip SHA-256 81c6d58fdd09c8af217e59dc752dc032dab32c29e204dd7f9d936592174bbf1a).

This module holds only the adapter-side logic that does not need the artifact or AgentDojo:

* the loopback-only guard URL check (all model traffic must go through the local budget guard);
* the DeepSeek wire normalisation applied to every request the artifact's ``OpenAILLM`` builds;
* a duck-typed client (``RoutedClient``) that exposes ``.chat.completions.create`` only;
* a per-role usage meter (no prompt text is ever stored);
* the judge probe that turns a provider's HTTP 400 "logprobs not supported" into the exact
  exception wording the released gate already handles (``AttriGuard.py`` fuzzy-survive fallback);
* the gate-route classifier used by the instrumented ``_fuzzy_survive``;
* the stage-plan expansion.

It imports nothing from the artifact or AgentDojo, so the unit tests run under any Python 3.11.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

DEEPSEEK_MODEL = "deepseek-flash"
THINKING_DISABLED: dict[str, Any] = {"thinking": {"type": "disabled"}}
# DeepSeek takes max_tokens; the lab's wire assertion forbids these two (configs/cross_model_pilot_v2.json).
FORBIDDEN_FIELDS = ("max_completion_tokens", "reasoning_effort")
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
ROLES = ("agent", "attenuation", "judge")
_SECRET_PATTERN = re.compile(r"sk-[A-Za-z0-9_\-]{8,}")


class AdapterRefusal(SystemExit):
    """Raised when a safety precondition fails before any model call."""


class LogprobsUnsupported(RuntimeError):
    """Raised by the judge probe so that the released gate takes its own JSON-only fallback.

    ``AttriGuard._fuzzy_survive`` retries without logprobs only when the exception text contains
    "logprobs" and, case-insensitively, "unsupported". The fixed message below satisfies both.
    """

    MESSAGE = "logprobs unsupported by provider (adapter translation of an HTTP 400 rejection)"

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


def require_loopback_base_url(url: str | None) -> str:
    """Return ``url`` without a trailing slash if it points at a loopback host, else refuse."""
    if not url:
        raise AdapterRefusal(
            "refusing: no guard URL. Set AUDITOR_GUARD_URL or OPENAI_BASE_URL to the local budget guard."
        )
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or host not in LOOPBACK_HOSTS:
        raise AdapterRefusal(
            "refusing: the model base URL must be the local budget guard on a loopback host "
            f"(got scheme={parts.scheme!r} host={host!r}); direct provider URLs are not allowed."
        )
    return url.rstrip("/")


def redact(text: str, secrets: Iterable[str] = ()) -> str:
    out = str(text)
    for secret in secrets:
        if secret and len(secret) >= 8:
            out = out.replace(secret, "[REDACTED]")
    return _SECRET_PATTERN.sub("sk-[REDACTED]", out)


def _is_sentinel(value: Any) -> bool:
    # openai._types.NOT_GIVEN / Omit; matched by type name so this module does not import openai.
    return type(value).__name__ in ("NotGiven", "Omit")


def _flatten_content(content: Any) -> Any:
    if not isinstance(content, list):
        return content
    texts = []
    for block in content:
        if isinstance(block, Mapping):
            texts.append(str(block.get("text", block.get("content", "")) or ""))
        else:
            texts.append(str(block))
    return "\n".join(texts)


def normalize_messages(messages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Same wire adaptation as the lab's ``deepseek_adapter._message_to_deepseek``.

    * ``developer`` role becomes ``system``;
    * the ``name`` field is dropped from tool messages (``tool_call_id`` identifies the call);
    * list-of-text-parts content is joined with newlines into one string.

    The artifact builds every message from a single text block, so the join is lossless here.
    """
    out: list[dict[str, Any]] = []
    for message in messages:
        msg = dict(message)
        if msg.get("role") == "developer":
            msg["role"] = "system"
        if msg.get("role") == "tool":
            msg.pop("name", None)
        if "content" in msg:
            msg["content"] = _flatten_content(msg["content"])
        out.append(msg)
    return out


@dataclass
class WireReport:
    dropped_fields: list[str] = field(default_factory=list)
    injected_max_tokens: bool = False
    stripped_logprobs: bool = False


def build_wire_params(
    params: Mapping[str, Any],
    *,
    model: str = DEEPSEEK_MODEL,
    max_tokens: int = 2048,
    allow_logprobs: bool = True,
) -> tuple[dict[str, Any], WireReport]:
    """Turn the artifact's ``chat.completions.create`` kwargs into a DeepSeek-safe request."""
    report = WireReport()
    clean = {k: v for k, v in params.items() if not _is_sentinel(v)}
    if clean.get("model") != model:
        raise ValueError(f"adapter only routes model {model!r}; artifact asked for {clean.get('model')!r}")
    for name in FORBIDDEN_FIELDS:
        if name in clean:
            clean.pop(name)
            report.dropped_fields.append(name)
    clean["messages"] = normalize_messages(clean.get("messages") or [])
    if "max_tokens" not in clean:
        clean["max_tokens"] = int(max_tokens)
        report.injected_max_tokens = True
    extra_body = dict(clean.get("extra_body") or {})
    extra_body.update(THINKING_DISABLED)
    clean["extra_body"] = extra_body
    if not allow_logprobs and ("logprobs" in clean or "top_logprobs" in clean):
        clean.pop("logprobs", None)
        clean.pop("top_logprobs", None)
        report.stripped_logprobs = True
    return clean, report


@dataclass
class RunContext:
    """Mutable per-run state shared by the clients, the judge probe and the instrumented gate."""

    episode_id: str = "-"
    logprobs_mode: str = "auto"  # auto | off
    logprobs_disabled: bool = False  # becomes True (sticky) after the first provider rejection

    @property
    def logprobs_allowed(self) -> bool:
        return self.logprobs_mode == "auto" and not self.logprobs_disabled


def _blank_counts() -> dict[str, int]:
    return {
        "requests": 0,
        "errors": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "missing_usage": 0,
        "finish_length": 0,
        "logprobs_returned": 0,
    }


class UsageMeter:
    """Counts usage per role for the whole run and for the current episode. Stores no text."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total = {role: _blank_counts() for role in ROLES}
        self.episode = {role: _blank_counts() for role in ROLES}

    def begin_episode(self) -> None:
        with self._lock:
            self.episode = {role: _blank_counts() for role in ROLES}

    def _bump(self, role: str, key: str, amount: int = 1) -> None:
        for bucket in (self.total, self.episode):
            bucket.setdefault(role, _blank_counts())[key] += amount

    def record(self, role: str, completion: Any) -> None:
        with self._lock:
            self._bump(role, "requests")
            usage = getattr(completion, "usage", None)
            if usage is None:
                self._bump(role, "missing_usage")
            else:
                self._bump(role, "prompt_tokens", int(getattr(usage, "prompt_tokens", 0) or 0))
                self._bump(role, "completion_tokens", int(getattr(usage, "completion_tokens", 0) or 0))
            choices = getattr(completion, "choices", None) or []
            if choices:
                if getattr(choices[0], "finish_reason", None) == "length":
                    self._bump(role, "finish_length")
                if getattr(choices[0], "logprobs", None) is not None:
                    self._bump(role, "logprobs_returned")

    def record_error(self, role: str) -> None:
        with self._lock:
            self._bump(role, "requests")
            self._bump(role, "errors")

    @staticmethod
    def tokens(bucket: Mapping[str, Mapping[str, int]]) -> int:
        return sum(v["prompt_tokens"] + v["completion_tokens"] for v in bucket.values())

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "episode": json.loads(json.dumps(self.episode)),
                "total": json.loads(json.dumps(self.total)),
            }


class RoutedClient:
    """Duck-typed stand-in for ``openai.OpenAI`` exposing ``chat.completions.create`` only.

    The artifact's ``OpenAILLM`` (``openai_llm_compat.py:238``) calls nothing else on its client.
    """

    def __init__(
        self,
        inner: Any,
        role: str,
        meter: UsageMeter,
        context: RunContext,
        *,
        model: str = DEEPSEEK_MODEL,
        max_tokens: int = 2048,
        artifact: str = "attriguard",
    ) -> None:
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}")
        self._inner = inner
        self.role = role
        self.meter = meter
        self.context = context
        self.model = model
        self.max_tokens = max_tokens
        self.artifact = artifact
        self.wire_reports = {"dropped_fields": set(), "injected_max_tokens": 0, "stripped_logprobs": 0}
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **params: Any) -> Any:
        wire, report = build_wire_params(
            params,
            model=self.model,
            max_tokens=self.max_tokens,
            allow_logprobs=self.context.logprobs_allowed,
        )
        self.wire_reports["dropped_fields"].update(report.dropped_fields)
        self.wire_reports["injected_max_tokens"] += int(report.injected_max_tokens)
        self.wire_reports["stripped_logprobs"] += int(report.stripped_logprobs)
        headers = dict(wire.pop("extra_headers", None) or {})
        headers.update(
            {
                "X-Auditor-Artifact": self.artifact,
                "X-Auditor-Role": self.role,
                "X-Auditor-Episode": str(self.context.episode_id)[:200],
            }
        )
        wire["extra_headers"] = headers
        try:
            completion = self._inner.chat.completions.create(**wire)
        except Exception:
            self.meter.record_error(self.role)
            raise
        self.meter.record(self.role, completion)
        return completion


def is_logprobs_rejection(exc: BaseException) -> bool:
    status = getattr(exc, "status_code", None)
    return status in (400, 422) and "logprob" in str(exc).lower()


def _last_assistant_text(messages: Sequence[Mapping[str, Any]]) -> str:
    for msg in reversed(list(messages or [])):
        if msg.get("role") == "assistant":
            return str(_flatten_content(msg.get("content")) or "")
    return ""


class JudgeProbe:
    """Wraps the judge LLM element. Duck-typed: the gate only calls ``judge_llm.query``.

    ``logprobs_mode``:
      * ``auto``: forward the gate's ``logprobs=True, top_logprobs=5``. If the provider rejects them with
        HTTP 400/422 mentioning logprobs, raise ``LogprobsUnsupported`` so the released fallback re-asks
        without logprobs, and stop sending logprobs for the rest of the run (sticky).
      * ``off``: never send logprobs; the gate then decides on the judge's JSON only.
    """

    name = "attriguard-judge-probe"

    def __init__(self, inner: Any, context: RunContext) -> None:
        self.inner = inner
        self.context = context
        self.calls = 0
        self.logprobs_rejections = 0
        self.last_raw = ""
        self.last_logprobs_present = False

    def query(self, query, runtime, env=None, messages=(), extra_args=None):  # noqa: ANN001
        args = dict(extra_args or {})
        if not self.context.logprobs_allowed:
            args.pop("logprobs", None)
            args.pop("top_logprobs", None)
        self.calls += 1
        try:
            result = self.inner.query(query, runtime, env, messages, args)
        except Exception as exc:
            if args.get("logprobs") and is_logprobs_rejection(exc):
                self.logprobs_rejections += 1
                self.context.logprobs_disabled = True
                raise LogprobsUnsupported() from None
            raise
        out_messages = result[3]
        extra = result[4]
        self.last_raw = _last_assistant_text(out_messages)
        self.last_logprobs_present = isinstance(extra, Mapping) and extra.get("logprobs") is not None
        return result


def classify_route(
    *,
    exact: bool,
    same_function: bool,
    has_judge: bool,
    judged: bool,
    raw: str,
    logprobs_present: bool,
    survived: bool,
) -> str:
    """Name the code path the released ``_fuzzy_survive`` took (NOTES.md section 4 rows 4, 5 and 15)."""
    verdict = "allow" if survived else "block"
    if exact:
        return "exact_fastpath"
    if not has_judge:
        return f"exact_only_{verdict}"
    if not same_function:
        return "name_mismatch_block"
    if not judged:
        return f"judge_not_called_{verdict}"
    parsed: Any = None
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            parsed = data.get("survive")
    except (TypeError, ValueError):
        parsed = None
    if isinstance(parsed, bool):
        route = f"judge_json_{verdict}"
        if logprobs_present and parsed != survived:
            route += "_logprob_override"
        return route
    return f"judge_parse_fallback_{verdict}"


# ---------------------------------------------------------------------------------------------
# Stage plan expansion


def task_number(task_id: str) -> int:
    try:
        return int(str(task_id).rsplit("_", 1)[1])
    except (IndexError, ValueError):
        return 10**9


def _select(spec: Any, available: Sequence[str], exclude: Iterable[str] = ()) -> list[str]:
    excluded = set(exclude)
    if spec in (None, "*"):
        chosen = list(available)
    else:
        missing = [t for t in spec if t not in available]
        if missing:
            raise ValueError(f"unknown task ids: {missing}")
        chosen = list(spec)
    return sorted((t for t in chosen if t not in excluded), key=task_number)


def expand_stage(
    config: Mapping[str, Any], stage: str, catalog: Mapping[str, Mapping[str, Sequence[str]]]
) -> list[dict[str, Any]]:
    """Expand a stage into an ordered episode list.

    ``catalog`` maps suite -> {"user_tasks": [...], "injection_tasks": [...]} from the installed AgentDojo.
    Order: suite, then user task; for each user task the benign episodes of every row come first, then
    each injection task across every row (rows interleaved, so a capped partial run stays paired).
    """
    stages = config.get("stages") or {}
    if stage not in stages:
        raise ValueError(f"unknown stage {stage!r}; known: {sorted(stages)}")
    spec = stages[stage]
    rows_def = config.get("rows") or {}
    row_ids = list(spec["rows"])
    for row_id in row_ids:
        if row_id not in rows_def:
            raise ValueError(f"stage {stage} names undefined row {row_id!r}")
    episodes: list[dict[str, Any]] = []
    for suite_name, suite_spec in spec["suites"].items():
        if suite_name not in catalog:
            raise ValueError(f"suite {suite_name!r} not in the installed benchmark")
        available_ut = list(catalog[suite_name]["user_tasks"])
        available_it = list(catalog[suite_name]["injection_tasks"])
        if "pairs" in suite_spec:
            pairs = [(str(u), str(i)) for u, i in suite_spec["pairs"]]
            for u, i in pairs:
                _select([u], available_ut)
                _select([i], available_it)
            user_tasks = sorted({u for u, _ in pairs}, key=task_number)
            pairs_by_ut = {u: [i for uu, i in pairs if uu == u] for u in user_tasks}
        else:
            user_tasks = _select(suite_spec.get("user_tasks", "*"), available_ut, suite_spec.get("exclude_user_tasks", ()))
            injections = _select(
                suite_spec.get("injection_tasks", "*"), available_it, suite_spec.get("exclude_injection_tasks", ())
            )
            pairs_by_ut = {u: list(injections) for u in user_tasks}
        for user_task in user_tasks:
            if spec.get("benign", False):
                for row_id in row_ids:
                    row = rows_def[row_id]
                    episodes.append(
                        {
                            "episode_id": f"{row_id}/{suite_name}/{user_task}/benign",
                            "row": row_id,
                            "suite": suite_name,
                            "user_task": user_task,
                            "injection_task": None,
                            "attack": None,
                            "defense": row.get("defense"),
                            "level": row.get("level"),
                        }
                    )
            if spec.get("attacked", True):
                for injection_task in pairs_by_ut[user_task]:
                    for row_id in row_ids:
                        row = rows_def[row_id]
                        episodes.append(
                            {
                                "episode_id": f"{row_id}/{suite_name}/{user_task}/{injection_task}",
                                "row": row_id,
                                "suite": suite_name,
                                "user_task": user_task,
                                "injection_task": injection_task,
                                "attack": row["attack"],
                                "defense": row.get("defense"),
                                "level": row.get("level"),
                            }
                        )
    return episodes


def summarize_episodes(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Per-row BU / UA / ASR with exact counts. AgentDojo ``security`` True means the injection succeeded."""
    rows: dict[str, dict[str, Any]] = {}
    for rec in records:
        if rec.get("status") != "done":
            continue
        row = rows.setdefault(
            rec["row"],
            {"benign_n": 0, "benign_utility": 0, "attacked_n": 0, "attacked_utility": 0, "attack_success": 0,
             "tokens": 0, "by_suite": {}},
        )
        suite = row["by_suite"].setdefault(
            rec["suite"], {"benign_n": 0, "benign_utility": 0, "attacked_n": 0, "attacked_utility": 0, "attack_success": 0}
        )
        row["tokens"] += int(rec.get("episode_tokens", 0) or 0)
        for bucket in (row, suite):
            if rec.get("injection_task") is None:
                bucket["benign_n"] += 1
                bucket["benign_utility"] += int(bool(rec.get("utility")))
            else:
                bucket["attacked_n"] += 1
                bucket["attacked_utility"] += int(bool(rec.get("utility")))
                bucket["attack_success"] += int(bool(rec.get("security")))
    for row in rows.values():
        for bucket in [row, *row["by_suite"].values()]:
            bucket["BU"] = _ratio(bucket["benign_utility"], bucket["benign_n"])
            bucket["UA"] = _ratio(bucket["attacked_utility"], bucket["attacked_n"])
            bucket["ASR"] = _ratio(bucket["attack_success"], bucket["attacked_n"])
        n = row["benign_n"] + row["attacked_n"]
        row["tokens_per_episode"] = round(row["tokens"] / n, 1) if n else None
    return rows


def _ratio(num: int, den: int) -> str | None:
    return f"{num}/{den} = {100.0 * num / den:.2f}%" if den else None
