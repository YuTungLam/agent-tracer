#!/usr/bin/env python3
"""Run the released PAA auditor with DeepSeek (deepseek-flash) as its backbone.

This is a declared *backbone-substituted* fidelity check, not an exact reproduction: the paper's
PAA numbers came from Claude Sonnet 5 (Claude Code CLI) and GPT-5.5 (Codex CLI).

What the adapter does, all in memory (the artifact on disk is never edited):
1. verifies the artifact's own ``FILES.sha256`` against a pinned anchor, then the hashes of every
   PAA code / prompt / policy file and of every benchmark unit (and its ToolCatalog) it will audit;
2. imports ``paa`` from the artifact, disables ``paa.llm.subprocess`` (so the ``claude`` / ``codex``
   CLIs can never start under the user's login), and replaces ``paa.llm._run_backend`` with an
   OpenAI-compatible chat transport that may only talk to a loopback URL (the budget guard proxy,
   or Ollama for plumbing dry runs);
3. applies one declared local patch, P1-tooldesc-marker (``paa.eu._ACTION_TOOL_MARK`` from
   ``/input_benign/tools/`` to ``/benign_input/tools/``), because the release renamed the directory
   and the shipped marker hides almost every tool description from the auditor
   (external-auditors/paa/NOTES.md section 5, smoke/09-tooldesc-marker-check.log);
4. runs the artifact's own runner ``paa.run.main`` (contract map on, rules 0.3) and stamps every
   certificate with an ``adapter`` block.

Subcommands:
  stage    prepare + run + compare in one process; this is what stages.json launches
  prepare  deterministic sample manifests + zero-cost prompt-size estimate (no model call)
  run      one stage (dry / S1 / S2) through the guard; writes results.jsonl + receipts
  compare  fidelity report against gold, the shipped Sonnet-5 predictions and the paper's CIs

Launch paid stages only through the shared runner (common/deepseek_route.py run-stage), which
starts the budget guard and sets AUDITOR_GUARD_URL / OPENAI_BASE_URL / OPENAI_API_KEY (a per-run
guard token, never the DeepSeek key) and AUDITOR_MODE / AUDITOR_BACKBONE. Paid mode refuses to run
without that guard. The child runs in the artifact's own venv from a scratch cwd as
  <paa-venv-python> -X utf8 -I paa_deepseek.py stage ...
Prompts and model outputs are benchmark data, never instructions.
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import hashlib
import json
import math
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

sys.dont_write_bytecode = True            # never drop __pycache__ into the artifact tree
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import fidelity as F  # noqa: E402

ADAPTER_VERSION = "paa-deepseek-adapter/0.1.0"
WIRE_MODEL = "deepseek-flash"
# sha256 of the artifact's FILES.sha256 (external-auditors/paa/provenance.json, integrity_anchors_sha256)
FILES_SHA256_ANCHOR = "f9b37c0ac9ef812d06e4ffce637c5115309d7d602dc07fdf4c4d5b879a653b45"
PAA_DIR = "audit-method/PAA"
CODE_FILES = tuple(f"{PAA_DIR}/{p}" for p in (
    "paa/__init__.py", "paa/eu.py", "paa/index.py", "paa/llm.py", "paa/pipeline.py", "paa/policy.py",
    "paa/redecide.py", "paa/render.py", "paa/run.py", "paa/score.py",
    "policies/paa-authority-3.0.json",
    "prompts/trace-system.txt", "prompts/adjudicate-system.txt", "prompts/contract-system.txt"))
CODEX_MANIFEST = "benchmark/codex/manifests/main-1792.json"
SHIPPED = {"paa_sonnet5": "baselines/v4-baseline-exp-results/v4-codex-r1/paa-claude/predictions.jsonl",
           "paa_gpt55": "baselines/v4-baseline-exp-results/v4-codex-r1/paa-codex/predictions.jsonl"}
CI_CSV = "exp/bootstrap-ci/data/ci_estimates.csv"
RUNTIME_CSV = "exp/runtime-accounting/data/runtime_accounting.csv"
TOOLDESC_PATCH = {
    "id": "P1-tooldesc-marker", "target": "paa.eu._ACTION_TOOL_MARK",
    "released": "/input_benign/tools/", "patched": "/benign_input/tools/",
    "why": "release renamed input_benign -> setting/benign_input (metadata/release_spec.json:60-61); "
           "the shipped marker registers TOOLDESC sources for 77/1792 Codex units only, the patched "
           "marker for all 1792 (7675 sources); restoring the paper's prompts exactly is UNVERIFIED",
}
STAGES = ("dry", "S1", "S2")
DEFAULT_MAX_REQUESTS = {"dry": 6, "S1": 30, "S2": 420}   # PAA issues at most 6 requests per unit
PRICE_SNAPSHOT = {"input_usd_per_m": 0.30, "output_usd_per_m": 1.20, "snapshot_date": "2026-09-30",
                  "status": "UNVERIFIED today",
                  "source": "agentdojo-lab configs/pilot_protocol_v1_draft.json budget.price_snapshots"}
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
DRY_STAGE_SYSTEM_CHARS_NOTE = "prompt sizes from paa.pipeline.audit(dry_run=True); no model call"


class RunAbort(BaseException):
    """Stops the whole run. BaseException on purpose: paa.run.main catches Exception per unit and
    would otherwise write a fail-open ERROR certificate (and later skip the unit on resume)."""


class IntegrityError(RuntimeError):
    pass


def utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(tmp, path)


def read_jsonl(path: str) -> list[dict[str, Any]]:
    out = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


# ----------------------------------------------------------------------------- integrity
def files_listing(root: str, anchor: str = FILES_SHA256_ANCHOR) -> dict[str, str]:
    path = os.path.join(root, "FILES.sha256")
    if not os.path.isfile(path):
        raise IntegrityError(f"FILES.sha256 not found under {root}")
    got = sha256_file(path)
    if got != anchor:
        raise IntegrityError(f"FILES.sha256 hash {got} != pinned anchor {anchor}")
    listed: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            digest, _, rel = line.rstrip("\n").partition("  ")
            if rel:
                listed[rel] = digest
    return listed


def rel_to(root: str, path: str) -> str:
    return os.path.relpath(os.path.abspath(path), os.path.abspath(root)).replace("\\", "/")


def verify_files(root: str, rels: list[str], listed: dict[str, str]) -> dict[str, Any]:
    problems = []
    for rel in rels:
        want = listed.get(rel)
        p = os.path.join(root, rel)
        if want is None:
            problems.append(f"not listed in FILES.sha256: {rel}")
        elif not os.path.isfile(p):
            problems.append(f"missing: {rel}")
        elif sha256_file(p) != want:
            problems.append(f"hash mismatch: {rel}")
    if problems:
        raise IntegrityError("; ".join(problems[:10]) + (f" (+{len(problems) - 10} more)" if len(problems) > 10 else ""))
    return {"files_sha256_anchor": FILES_SHA256_ANCHOR, "verified_files": len(rels), "problems": 0}


def unit_files(root: str, manifest: list[dict[str, Any]]) -> list[str]:
    rels: set[str] = set()
    for it in manifest:
        f = it["file"] if os.path.isabs(it["file"]) else os.path.join(root, it["file"])
        rels.add(rel_to(root, f))
        cat = os.path.join(os.path.dirname(f), "ToolCatalog.json")
        if os.path.exists(cat):
            rels.add(rel_to(root, cat))
    return sorted(rels)


# ----------------------------------------------------------------------------- artifact import
class _NoSubprocess:
    """Replaces paa.llm.subprocess: any attempt to start the claude / codex CLI fails loudly."""
    TimeoutExpired = TimeoutError

    @staticmethod
    def run(*_a, **_k):
        raise RunAbort("subprocess is disabled by the PAA DeepSeek adapter (no claude/codex CLI)")


def require_utf8() -> None:
    if not sys.flags.utf8_mode:
        raise SystemExit("PAA opens files without an encoding; run with `python -X utf8` (NOTES.md section 2)")


def import_paa(root: str):
    require_utf8()
    pkg = os.path.join(os.path.abspath(root), *PAA_DIR.split("/"))
    if pkg not in sys.path:
        sys.path.insert(0, pkg)
    import paa.eu as E  # noqa: E402
    import paa.llm as L  # noqa: E402
    import paa.pipeline as P  # noqa: E402
    import paa.run as R  # noqa: E402
    L.subprocess = _NoSubprocess
    return L, E, P, R


def apply_tooldesc_patch(E, mode: str) -> dict[str, Any]:
    cur = getattr(E, "_ACTION_TOOL_MARK", None)
    if cur not in (TOOLDESC_PATCH["released"], TOOLDESC_PATCH["patched"]):
        raise IntegrityError(f"unexpected paa.eu._ACTION_TOOL_MARK={cur!r}; refusing to patch")
    if mode == "patched":
        E._ACTION_TOOL_MARK = TOOLDESC_PATCH["patched"]
    elif mode == "released":
        E._ACTION_TOOL_MARK = TOOLDESC_PATCH["released"]
    else:
        raise ValueError(f"tooldesc mode {mode!r}")
    return {"id": TOOLDESC_PATCH["id"], "target": TOOLDESC_PATCH["target"], "mode": mode,
            "value": E._ACTION_TOOL_MARK, "applied": mode == "patched", "why": TOOLDESC_PATCH["why"]}


def tooldesc_count(E, file: str, unit_index: int) -> int:
    eu = E.load_eu(file, unit_index)
    return sum(1 for s in eu.sources.values() if s.kind == "tooldesc")


# ----------------------------------------------------------------------------- budget + ledger
class ClientBudget:
    """Client-side cap (defence in depth; the guard enforces its own). Each request reserves its
    worst case (input from prompt chars at a conservative chars/token, output at max_tokens) and
    is refused if spent + reserved + worst case would cross a cap. Cumulative across resumes."""

    def __init__(self, cap_usd: float, cap_tokens: int, max_requests: int, price_in: float,
                 price_out: float, max_tokens: int, chars_per_token: float = 2.5,
                 spent_requests: int = 0, spent_tokens: int = 0, spent_usd: float = 0.0):
        self.cap_usd, self.cap_tokens, self.max_requests = float(cap_usd), int(cap_tokens), int(max_requests)
        self.price_in, self.price_out, self.max_tokens = float(price_in), float(price_out), int(max_tokens)
        self.cpt = float(chars_per_token)
        self.requests, self.tokens, self.usd = int(spent_requests), int(spent_tokens), float(spent_usd)
        self.res_tokens, self.res_usd = 0, 0.0
        self._lock = threading.Lock()

    def usd_of(self, prompt_tokens: int, completion_tokens: int) -> float:
        return prompt_tokens * self.price_in / 1e6 + completion_tokens * self.price_out / 1e6

    def reserve(self, prompt_chars: int) -> tuple[int, float]:
        est_in = int(math.ceil(prompt_chars / self.cpt))
        est_tok = est_in + self.max_tokens
        est_usd = self.usd_of(est_in, self.max_tokens)
        with self._lock:
            if self.requests + 1 > self.max_requests:
                raise RunAbort(f"client request cap reached ({self.requests}/{self.max_requests})")
            if self.tokens + self.res_tokens + est_tok > self.cap_tokens:
                raise RunAbort(f"client token cap would be crossed ({self.tokens}+{self.res_tokens}+{est_tok} > {self.cap_tokens})")
            if self.usd + self.res_usd + est_usd > self.cap_usd + 1e-12:
                raise RunAbort(f"client USD cap would be crossed ({self.usd:.4f}+{self.res_usd:.4f}+{est_usd:.4f} > {self.cap_usd})")
            self.requests += 1
            self.res_tokens += est_tok
            self.res_usd += est_usd
        return est_tok, est_usd

    def settle(self, ticket: tuple[int, float], prompt_tokens: int | None, completion_tokens: int | None) -> float:
        with self._lock:
            self.res_tokens -= ticket[0]
            self.res_usd -= ticket[1]
            if prompt_tokens is None or completion_tokens is None:
                tok, usd = ticket                                      # unknown usage: charge worst case
            else:
                tok, usd = prompt_tokens + completion_tokens, self.usd_of(prompt_tokens, completion_tokens)
            self.tokens += tok
            self.usd += usd
            return usd

    def release(self, ticket: tuple[int, float]) -> None:
        """A request that provably produced no billable response (connection refused)."""
        with self._lock:
            self.res_tokens -= ticket[0]
            self.res_usd -= ticket[1]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"requests": self.requests, "tokens": self.tokens, "usd": round(self.usd, 6),
                    "cap_usd": self.cap_usd, "cap_tokens": self.cap_tokens, "max_requests": self.max_requests}


class Ledger:
    """One JSON line per request: ids, stage, status and usage only (no prompt or output text)."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def append(self, row: dict[str, Any]) -> None:
        row = dict(row, ts=utcnow())
        with self._lock, open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    @staticmethod
    def totals(path: str) -> tuple[int, int, float]:
        req = tok = 0
        usd = 0.0
        for r in read_jsonl(path):
            if r.get("sent"):
                req += 1
                tok += int(r.get("charged_tokens") or 0)
                usd += float(r.get("charged_usd") or 0.0)
        return req, tok, usd


# ----------------------------------------------------------------------------- transport
def check_base_url(url: str) -> str:
    u = urllib.parse.urlsplit(url or "")
    if u.scheme != "http" or (u.hostname or "") not in LOOPBACK:
        raise ValueError("base URL must be a loopback http URL (the local budget guard or Ollama); "
                         f"got scheme={u.scheme!r} host={u.hostname!r}. Direct remote calls are refused.")
    return url.rstrip("/")


_BUDGET_WORDS = ("budget", "cap reached", "cap exceeded", "refus", "quota")
_LENGTH_WORDS = ("context length", "context_length", "maximum context", "too long", "too many tokens",
                 "exceeds the model", "max_seq", "prompt is too")


def classify_http_error(status: int, body: str) -> str:
    """guard-refusal | systemic | retryable | unit-too-long | other."""
    low = (body or "").lower()
    if status == 402 or "auditor_guard_refusal" in low or (status == 429 and any(w in low for w in _BUDGET_WORDS)):
        return "guard-refusal"                  # common/deepseek_route.py refuses with HTTP 402
    if status in (401, 403, 404):
        return "systemic"                       # key, permission or model id: every request would fail
    if status == 429 or status >= 500:
        return "retryable"
    if status in (400, 413, 422) and any(w in low for w in _LENGTH_WORDS):
        return "unit-too-long"
    if status == 400:
        return "systemic"                       # request shape (e.g. an unsupported field): stop and fix
    return "other"


class ChatTransport:
    """Drop-in for paa.llm._run_backend: (system, prompt, cfg) -> (stdout, stderr, rc, timed_out).

    Returns a Claude-CLI-shaped JSON envelope so the artifact's own _extract_json, validation,
    retry and cache logic run unchanged. Usage is reported as input_tokens / output_tokens."""

    def __init__(self, *, base_url: str, api_key: str | None, wire_model: str, max_tokens: int,
                 temperature: float, json_mode: bool, budget: ClientBudget, ledger: Ledger,
                 stage_of: Callable[[str], str], abort: threading.Event, tls: threading.local,
                 on_error: str = "abort", http_retries: int = 2, backoff_s: tuple[float, ...] = (10.0, 30.0),
                 send_thinking_disabled: bool = True):
        self.url = check_base_url(base_url) + "/chat/completions"
        self._key = api_key or ""
        self.wire_model = wire_model
        self.max_tokens = int(max_tokens)
        self.temperature = float(temperature)
        self.json_mode = bool(json_mode)
        self.budget, self.ledger, self.stage_of = budget, ledger, stage_of
        self.abort, self.tls = abort, tls
        if on_error not in ("abort", "fail-open"):
            raise ValueError("on_error must be abort or fail-open")
        self.on_error = on_error
        self.http_retries = int(http_retries)
        self.backoff_s = backoff_s
        self.send_thinking_disabled = send_thinking_disabled
        self.seq = 0
        self._seq_lock = threading.Lock()

    def _redact(self, s: str) -> str:
        s = s or ""
        return s.replace(self._key, "[REDACTED]") if self._key else s

    def body(self, system: str, prompt: str) -> dict[str, Any]:
        b: dict[str, Any] = {"model": self.wire_model,
                             "messages": [{"role": "system", "content": system},
                                          {"role": "user", "content": prompt}],
                             "temperature": self.temperature, "max_tokens": self.max_tokens, "stream": False}
        if self.send_thinking_disabled:
            b["thinking"] = {"type": "disabled"}
        if self.json_mode:
            b["response_format"] = {"type": "json_object"}
        return b

    def _fail(self, msg: str, timed_out: bool = False):
        self.tls.failures = getattr(self.tls, "failures", 0) + 1
        if self.on_error == "abort":
            self.abort.set()
            raise RunAbort(msg)
        return "", msg[-2000:], (-1 if timed_out else 1), timed_out

    def __call__(self, system: str, prompt: str, cfg) -> tuple[str, str, int, bool]:
        if self.abort.is_set():
            raise RunAbort("run aborted earlier")
        stage = self.stage_of(system)
        data = json.dumps(self.body(system, prompt), ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        timeout = float(getattr(cfg, "timeout_s", 900) or 900)
        for attempt in range(self.http_retries + 1):
            try:
                ticket = self.budget.reserve(len(system) + len(prompt))
            except RunAbort:
                self.abort.set()
                raise
            with self._seq_lock:
                self.seq += 1
                seq = self.seq
            row = {"seq": seq, "unit": getattr(self.tls, "unit", None), "stage": stage, "http_try": attempt + 1,
                   "wire_model": self.wire_model, "prompt_chars": len(system) + len(prompt), "sent": True}
            t0 = time.time()
            req = urllib.request.Request(self.url, data=data, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    status = r.status
                    raw = r.read().decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                status = e.code
                raw = self._redact(e.read().decode("utf-8", "replace"))[:600]
                usd = self.budget.settle(ticket, None, None) if status < 400 else self._release(ticket)
                row.update(http_status=status, ok=False, latency_s=round(time.time() - t0, 2),
                           error_kind="http", error_head=raw[:300], charged_tokens=0, charged_usd=usd)
                kind = classify_http_error(status, raw)
                row["error_class"] = kind
                self.ledger.append(row)
                if kind in ("guard-refusal", "systemic"):
                    self.abort.set()
                    raise RunAbort(f"{kind} (HTTP {status}): {raw[:200]}")
                if kind == "retryable" and attempt < self.http_retries:
                    time.sleep(self.backoff_s[min(attempt, len(self.backoff_s) - 1)])
                    continue
                if kind == "unit-too-long":
                    # deterministic for this prompt: let PAA record the unit as UNKNOWN (fail-open),
                    # flagged in the certificate's adapter block; do not stop the stage
                    self.tls.failures = getattr(self.tls, "failures", 0) + 1
                    return "", f"HTTP {status} prompt too long: {raw[:300]}", 1, False
                return self._fail(f"HTTP {status} from {self.url}: {raw[:300]}")
            except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as e:
                timed_out = isinstance(e, (socket.timeout, TimeoutError)) or "timed out" in str(e)
                # a timeout may still be billed upstream: charge the reservation; refused connection: release
                usd = self.budget.settle(ticket, None, None) if timed_out else self._release(ticket)
                row.update(http_status=None, ok=False, latency_s=round(time.time() - t0, 2),
                           error_kind="timeout" if timed_out else "connection",
                           error_head=self._redact(repr(e))[:300],
                           charged_tokens=(ticket[0] if timed_out else 0), charged_usd=usd)
                self.ledger.append(row)
                if not timed_out:                    # guard or upstream unreachable: every unit would fail
                    self.abort.set()
                    raise RunAbort(f"connection error to {self.url}: {self._redact(repr(e))[:200]}")
                return self._fail(f"transport timeout: {e!r}", timed_out)
            try:
                resp = json.loads(raw)
                choice = (resp.get("choices") or [{}])[0]
                text = (choice.get("message") or {}).get("content") or ""
                finish = choice.get("finish_reason")
                u = resp.get("usage") or {}
                pt, ct = u.get("prompt_tokens"), u.get("completion_tokens")
            except (json.JSONDecodeError, AttributeError, IndexError, TypeError):
                usd = self.budget.settle(ticket, None, None)
                row.update(http_status=status, ok=False, latency_s=round(time.time() - t0, 2),
                           error_kind="bad-response", charged_tokens=ticket[0], charged_usd=usd)
                self.ledger.append(row)
                return self._fail(f"unparseable response from {self.url}")
            usd = self.budget.settle(ticket, pt, ct)
            row.update(http_status=status, ok=True, latency_s=round(time.time() - t0, 2),
                       prompt_tokens=pt, completion_tokens=ct,
                       prompt_cache_hit_tokens=u.get("prompt_cache_hit_tokens"),
                       finish_reason=finish, response_model=resp.get("model"),
                       charged_tokens=(pt + ct) if isinstance(pt, int) and isinstance(ct, int) else ticket[0],
                       charged_usd=usd, output_chars=len(text))
            self.ledger.append(row)
            self.tls.requests = getattr(self.tls, "requests", 0) + 1
            self.tls.prompt_tokens = getattr(self.tls, "prompt_tokens", 0) + int(pt or 0)
            self.tls.completion_tokens = getattr(self.tls, "completion_tokens", 0) + int(ct or 0)
            env = {"type": "result", "subtype": "success", "is_error": False, "num_turns": 1,
                   "result": text, "total_cost_usd": None,
                   "duration_ms": int((time.time() - t0) * 1000),
                   "usage": {"input_tokens": int(pt or 0), "output_tokens": int(ct or 0),
                             "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
                             "x_prompt_cache_hit_tokens": u.get("prompt_cache_hit_tokens"),
                             "x_finish_reason": finish, "x_response_model": resp.get("model"),
                             "x_wire_model": self.wire_model}}
            return json.dumps(env, ensure_ascii=False), "", 0, False
        return self._fail("retries exhausted")

    def _release(self, ticket) -> float:
        self.budget.release(ticket)
        return 0.0


def stage_resolver(P) -> Callable[[str], str]:
    table = ((P._TRACE_SYS, "trace"), (P._ADJ_SYS, "adjudicate"), (P._CONTRACT_SYS, "contract"))

    def stage_of(system: str) -> str:
        for s, name in table:
            if system is s or system == s:
                return name
        return "unknown"
    return stage_of


def make_audit_wrapper(orig, idmap: dict[tuple[str, int], str], tls: threading.local,
                       abort: threading.Event, stamp: dict[str, Any]):
    def audit(file, unit_index, cfg, **kw):
        if abort.is_set():
            raise RunAbort("run aborted earlier")
        tls.unit = idmap.get((file, unit_index))
        tls.requests = tls.prompt_tokens = tls.completion_tokens = tls.failures = 0
        cert = orig(file, unit_index, cfg, **kw)
        cert["adapter"] = dict(stamp, unit_requests=tls.requests, unit_prompt_tokens=tls.prompt_tokens,
                               unit_completion_tokens=tls.completion_tokens,
                               unit_transport_failures=tls.failures)
        return cert
    return audit


# ----------------------------------------------------------------------------- helpers
def _read_text(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def git_commit(start: str) -> str | None:
    """Read the agent-tracer commit from .git without running git."""
    d = os.path.abspath(start)
    while True:
        g = os.path.join(d, ".git")
        if os.path.isdir(g):
            try:
                head = _read_text(os.path.join(g, "HEAD")).strip()
                if not head.startswith("ref:"):
                    return head
                ref = head.split(" ", 1)[1].strip()
                p = os.path.join(g, *ref.split("/"))
                if os.path.exists(p):
                    return _read_text(p).strip()
                packed = os.path.join(g, "packed-refs")
                if os.path.exists(packed):
                    for line in _read_text(packed).splitlines():
                        if line.strip().endswith(" " + ref):
                            return line.split(" ", 1)[0]
            except OSError:
                return None
            return None
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def adapter_hashes() -> dict[str, str]:
    return {n: sha256_file(os.path.join(_HERE, n)) for n in ("paa_deepseek.py", "fidelity.py")}


def resolve(arg: str | None, env: str, what: str, required: bool = True) -> str | None:
    v = arg or os.environ.get(env)
    if required and not v:
        raise SystemExit(f"{what} is required (--{what.replace('_', '-')} or env {env})")
    return os.path.abspath(v) if v else None


def resolve_mode(a) -> None:
    """Reconcile --dry-run-ollama with the runner's AUDITOR_MODE / AUDITOR_BACKBONE (common/deepseek_route.py)."""
    env_mode = os.environ.get("AUDITOR_MODE")
    if env_mode == "ollama-dry-run":
        backbone = os.environ.get("AUDITOR_BACKBONE") or "ollama:unknown"
        model = backbone.split(":", 1)[1] if backbone.startswith("ollama:") else backbone
        if a.dry_run_ollama and a.dry_run_ollama != model:
            raise SystemExit(f"--dry-run-ollama {a.dry_run_ollama!r} disagrees with the runner backbone {backbone!r}")
        a.dry_run_ollama = model
    elif env_mode == "deepseek" and a.dry_run_ollama:
        raise SystemExit("the runner started a paid DeepSeek stage; --dry-run-ollama is not allowed here")
    elif env_mode not in (None, "deepseek", "ollama-dry-run"):
        raise SystemExit(f"unknown AUDITOR_MODE {env_mode!r}")


def resolve_base_url(a, dry: bool) -> str:
    """Paid mode only runs under the shared guard: AUDITOR_GUARD_URL must be a loopback URL and
    OPENAI_BASE_URL must point at it (the same check as common.deepseek_route.require_guard)."""
    guard = os.environ.get("AUDITOR_GUARD_URL") or ""
    if guard:
        if os.environ.get("OPENAI_BASE_URL") != guard:
            raise SystemExit("OPENAI_BASE_URL does not point at the auditor guard")
        if a.base_url and a.base_url.rstrip("/") != guard.rstrip("/"):
            raise SystemExit("--base-url disagrees with AUDITOR_GUARD_URL")
        return check_base_url(guard)
    if not dry:
        raise SystemExit("paid mode runs only under the auditor guard; launch through "
                         "common/deepseek_route.py run-stage (AUDITOR_GUARD_URL is not set)")
    if not a.base_url:
        raise SystemExit("a dry run outside the guard needs --base-url (e.g. http://localhost:11434/v1 with --direct-ollama)")
    return check_base_url(a.base_url)


def stage_files(work: str, stage: str) -> tuple[str, str]:
    key = {"dry": "dry", "S1": "s1", "S2": "s2"}[stage]
    return os.path.join(work, f"{key}_manifest.json"), os.path.join(work, f"{key}_gold.json")


# ----------------------------------------------------------------------------- prepare
def cmd_prepare(a) -> int:
    root = resolve(a.artifact_root, "PAA_ARTIFACT_ROOT", "artifact_root")
    work = resolve(a.work, "PAA_WORK_DIR", "work")
    os.makedirs(work, exist_ok=True)
    listed = files_listing(root)
    integ = verify_files(root, list(CODE_FILES) + [CODEX_MANIFEST, CI_CSV, RUNTIME_CSV] + list(SHIPPED.values()), listed)
    items = read_json(os.path.join(root, CODEX_MANIFEST))
    sample = F.draw_sample(items, a.n_block, a.n_pass, a.tag)
    s1 = F.pick_s1(sample)
    pop = {}
    for it in items:
        c = "/".join(F.cell_of(it))
        pop[c] = pop.get(c, 0) + 1

    L, E, P, _R = import_paa(root)

    def no_model(*_a, **_k):
        raise RunAbort("no model call allowed in prepare")
    L._run_backend = no_model
    s2_manifest = F.auditor_manifest(sample, root)
    integ_units = verify_files(root, unit_files(root, s2_manifest), listed)

    # zero-cost prompt sizes (dry-run audit with the patch on) and the patch's effect
    sizes: dict[str, dict[str, int]] = {}
    patch_effect = []
    tmp = tempfile.mkdtemp(prefix="paa-prepare-cache-")
    try:
        cfg = L.LLMConfig(model="prepare-dry", effort="low", cache_dir=tmp, dry_run=True, backend="claude")
        for m in s2_manifest:
            apply_tooldesc_patch(E, "released")
            n_rel = tooldesc_count(E, m["file"], m["unit_index"])
            apply_tooldesc_patch(E, "patched")
            n_pat = tooldesc_count(E, m["file"], m["unit_index"])
            patch_effect.append({"eval_unit_id": m["eval_unit_id"], "tooldesc_released": n_rel, "tooldesc_patched": n_pat})
            cert = P.audit(m["file"], m["unit_index"], cfg, use_contract=True, contract_cfg=cfg, rules="0.3")
            row = {}
            for c in cert.get("calls", []):
                at = (c.get("attempts") or [{}])[0]
                row[c.get("stage")] = int(at.get("prompt_chars") or 0) + int(at.get("system_chars") or 0)
            sizes[m["eval_unit_id"]] = row
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    adj_sys = len(P._ADJ_SYS)
    dry = min(s1, key=lambda r: sum(sizes[r["eval_unit_id"]].values()))

    for name, rows in (("s2", sample), ("s1", s1), ("dry", [dry])):
        write_json(os.path.join(work, f"{name}_manifest.json"), F.auditor_manifest(rows, root))
        write_json(os.path.join(work, f"{name}_gold.json"), F.gold_slice(rows))
    est = estimate(sizes, adj_sys, sample, s1, a, root)
    receipt = {"adapter_version": ADAPTER_VERSION, "created_utc": utcnow(), "model_requests": 0,
               "artifact_integrity": {"code_and_reference_files": integ, "sampled_units": integ_units},
               "sample": {"tag": a.tag, "n_block": a.n_block, "n_pass": a.n_pass, "one_per_pair": True,
                          "population": {"units": len(items), "cells": pop},
                          "s2_ids": [r["eval_unit_id"] for r in sample], "s1_ids": [r["eval_unit_id"] for r in s1],
                          "dry_id": dry["eval_unit_id"],
                          "s2_cells": dict(sorted(_count(r["cell"] for r in sample).items()))},
               "tooldesc_patch_effect": {"units": len(patch_effect),
                                         "released_total": sum(p["tooldesc_released"] for p in patch_effect),
                                         "patched_total": sum(p["tooldesc_patched"] for p in patch_effect),
                                         "per_unit": patch_effect},
               "prompt_chars": sizes, "estimate": est,
               "agent_tracer_commit": git_commit(_HERE), "adapter_sha256": adapter_hashes()}
    write_json(os.path.join(work, "prepare_receipt.json"), receipt)
    write_json(os.path.join(work, "cell_population.json"), pop)
    print(json.dumps({"work": work, "s2": len(sample), "s1": [r["eval_unit_id"] for r in s1],
                      "dry": dry["eval_unit_id"], "tooldesc_released_total": receipt["tooldesc_patch_effect"]["released_total"],
                      "tooldesc_patched_total": receipt["tooldesc_patch_effect"]["patched_total"],
                      "estimate": est["stages"]}, indent=1))
    return 0


def _count(xs):
    out: dict[str, int] = {}
    for x in xs:
        out[x] = out.get(x, 0) + 1
    return out


def estimate(sizes: dict[str, dict[str, int]], adj_sys_chars: int, sample, s1, a, root: str) -> dict[str, Any]:
    """Token / USD estimate per stage. Every parameter below is a stated assumption (UNVERIFIED)."""
    cpt_central, cpt_cons = 3.9, 3.0          # qwen2.5 measured 3.89-4.05 chars/token on PAA prompts
    out_central = {"contract": 500, "trace": 3000, "adjudicate": 1500}
    att_central = {"contract": 1.0, "trace": 1.5, "adjudicate": 1.5}
    p_adj = 1 - 199 / 1792                    # shipped Sonnet-5 PASS_FAST share skips the adjudicator
    pin, pout = a.price_in_per_m, a.price_out_per_m

    def unit_tokens(uid: str, upper: bool) -> tuple[float, float]:
        s = sizes[uid]
        c, t = s.get("contract", 0), s.get("trace", 0)
        adj = adj_sys_chars + (1.0 if upper else 0.5) * max(0, t - 6461)
        cpt = cpt_cons if upper else cpt_central
        if upper:
            tin = 2 * (c + t + adj) / cpt
            tout = 6 * a.max_tokens
        else:
            tin = (att_central["contract"] * c + att_central["trace"] * t + p_adj * att_central["adjudicate"] * adj) / cpt
            tout = (att_central["contract"] * out_central["contract"] + att_central["trace"] * out_central["trace"]
                    + p_adj * att_central["adjudicate"] * out_central["adjudicate"])
        return tin, tout

    def stage(rows) -> dict[str, Any]:
        res = {}
        for name, upper in (("central", False), ("upper", True)):
            tin = tout = 0.0
            for r in rows:
                i, o = unit_tokens(r["eval_unit_id"], upper)
                tin += i
                tout += o
            res[name] = {"input_tokens": int(tin), "output_tokens": int(tout),
                         "usd": round(tin * pin / 1e6 + tout * pout / 1e6, 4)}
        return res

    ref = None
    try:
        with open(os.path.join(root, RUNTIME_CSV), encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row["corpus"] == "Codex" and row["auditor"] == "PAA" and row["backend"] == "S5":
                    ref = {"tok_med": int(row["tok_med"]), "tok_p90": int(row["tok_p90"]),
                           "req_med": row["req_med"], "req_max": row["req_max"], "source": RUNTIME_CSV,
                           "note": "Claude Code CLI tokens incl. cache reads/writes; not DeepSeek tokens"}
    except (OSError, KeyError, ValueError):
        pass
    trace_chars = sorted(sizes[r["eval_unit_id"]].get("trace", 0) for r in sample)
    return {"status": "UNVERIFIED estimate",
            "assumptions": {"chars_per_token_central": cpt_central, "chars_per_token_upper": cpt_cons,
                            "chars_per_token_source": "external-auditors/paa/smoke/toy-ollama/ollama_raw_log.json (qwen2.5 tokenizer proxy)",
                            "output_tokens_per_attempt_central": out_central, "attempts_central": att_central,
                            "adjudicate_share": round(p_adj, 4),
                            "adjudicate_prompt": "ADJ system + 0.5x (central) / 1.0x (upper) of the trace prompt body",
                            "upper": "2 attempts per stage (6 requests), every output at max_tokens",
                            "max_tokens": a.max_tokens, "price": PRICE_SNAPSHOT | {"input_usd_per_m": pin, "output_usd_per_m": pout},
                            "contract_cache_sharing": "ignored (conservative)"},
            "trace_prompt_chars_s2": {"min": trace_chars[0], "median": trace_chars[len(trace_chars) // 2],
                                      "max": trace_chars[-1]},
            "sonnet5_reference_per_unit": ref,
            "stages": {"S1": stage(s1), "S2": stage(sample)}}


# ----------------------------------------------------------------------------- run
def cmd_run(a) -> int:
    root = resolve(a.artifact_root, "PAA_ARTIFACT_ROOT", "artifact_root")
    work = resolve(a.work, "PAA_WORK_DIR", "work")
    out = resolve(a.out, "PAA_OUT_DIR", "out")
    if a.stage not in STAGES:
        raise SystemExit(f"--stage must be one of {STAGES}")
    resolve_mode(a)
    dry = bool(a.dry_run_ollama)
    if a.stage == "dry" and not dry:
        raise SystemExit("stage 'dry' requires an Ollama dry run (runner --dry-run-ollama, or --dry-run-ollama MODEL)")
    if a.direct_ollama and not dry:
        raise SystemExit("--direct-ollama is only valid with --dry-run-ollama")
    base_url = resolve_base_url(a, dry)
    if a.direct_ollama and urllib.parse.urlsplit(base_url).port != 11434:
        raise SystemExit("--direct-ollama expects the local Ollama port 11434")
    wire_model = a.dry_run_ollama if a.direct_ollama else WIRE_MODEL
    cache_model = WIRE_MODEL if not dry else f"{WIRE_MODEL}~dryrun-ollama:{a.dry_run_ollama}"
    mode = "dry-run-ollama" if dry else "deepseek"
    price_in, price_out = (0.0, 0.0) if dry else (a.price_in_per_m, a.price_out_per_m)

    manifest_path, gold_path = stage_files(work, a.stage)
    manifest = read_json(manifest_path)
    os.makedirs(out, exist_ok=True)
    marker = os.path.join(out, "adapter_mode.json")
    want_marker = {"mode": mode, "cache_model": cache_model, "stage": a.stage, "tooldesc": a.tooldesc,
                   "contract": not a.no_contract, "rules": "0.3", "max_tokens": a.max_tokens,
                   "temperature": a.temperature, "json_mode": a.json_mode}
    if os.path.exists(marker):
        have = read_json(marker)
        if have != want_marker:
            raise SystemExit(f"out dir was used with a different configuration: {have} != {want_marker}; use a new --out")
    else:
        write_json(marker, want_marker)

    listed = files_listing(root)
    integ = {"code": verify_files(root, list(CODE_FILES), listed),
             "units": verify_files(root, unit_files(root, manifest), listed)}
    L, E, P, R = import_paa(root)
    patch = apply_tooldesc_patch(E, a.tooldesc)

    ledger_path = os.path.join(out, "adapter_ledger.jsonl")
    s_req, s_tok, s_usd = Ledger.totals(ledger_path)
    max_requests = a.max_requests if a.max_requests is not None else DEFAULT_MAX_REQUESTS[a.stage]
    budget = ClientBudget(a.cap_usd, a.cap_tokens, max_requests, price_in, price_out, a.max_tokens,
                          spent_requests=s_req, spent_tokens=s_tok, spent_usd=s_usd)
    abort = threading.Event()
    tls = threading.local()
    api_key = os.environ.get("OPENAI_API_KEY") or None
    transport = ChatTransport(base_url=base_url, api_key=api_key, wire_model=wire_model,
                              max_tokens=a.max_tokens, temperature=a.temperature, json_mode=a.json_mode,
                              budget=budget, ledger=Ledger(ledger_path), stage_of=stage_resolver(P),
                              abort=abort, tls=tls, on_error=a.on_transport_error, http_retries=a.http_retries)
    L._run_backend = transport
    stamp = {"adapter_version": ADAPTER_VERSION, "mode": mode, "backbone": WIRE_MODEL,
             "wire_model": wire_model, "cache_model_tag": cache_model, "patches": [patch],
             "variant": {"contract": not a.no_contract, "rules": "0.3", "tooldesc": a.tooldesc,
                         "temperature": a.temperature, "max_tokens": a.max_tokens, "json_mode": a.json_mode,
                         "thinking": "disabled"},
             "fidelity_class": "backbone-substituted (paper: Claude Sonnet 5 / GPT-5.5 via CLI)",
             "version_note": "cert.version is the artifact's string for backend=claude; the transport is replaced"}
    idmap = {(m["file"], m["unit_index"]): m["eval_unit_id"] for m in manifest}
    R.audit = make_audit_wrapper(R.audit, idmap, tls, abort, stamp)

    argv = ["--manifest", manifest_path, "--out", out, "--model", cache_model, "--effort", "low",
            "--workers", str(a.workers), "--timeout", str(a.timeout), "--backend", "claude", "--rules", "0.3"]
    if not a.no_contract:
        argv.append("--contract")
    receipt = {"adapter_version": ADAPTER_VERSION, "stage": a.stage, "mode": mode, "started_utc": utcnow(),
               "artifact_integrity": integ, "patches": [patch], "base_url": base_url,
               "wire_model": wire_model, "cache_model_tag": cache_model, "paa_run_argv": argv,
               "manifest_sha256": sha256_file(manifest_path), "gold_sha256": sha256_file(gold_path),
               "units": len(manifest), "agent_tracer_commit": git_commit(_HERE),
               "adapter_sha256": adapter_hashes(), "price": (PRICE_SNAPSHOT if not dry else "local model, $0"),
               "budget_at_start": budget.snapshot(), "python": sys.version.split()[0],
               "key_present": bool(api_key)}
    status, reason, rc = "completed", None, 0
    try:
        R.main(argv)
    except RunAbort as e:
        status, reason, rc = "aborted", str(e)[:500], 3
    finally:
        results = os.path.join(out, "results.jsonl")
        done = read_jsonl(results)
        receipt.update({"finished_utc": utcnow(), "status": status, "abort_reason": reason,
                        "budget_at_end": budget.snapshot(), "results_lines": len(done),
                        "results_sha256": sha256_file(results) if os.path.exists(results) else None,
                        "statuses": _count(r.get("status") for r in done)})
        with open(os.path.join(out, "adapter_receipts.jsonl"), "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(receipt, ensure_ascii=False) + "\n")
    print(json.dumps({"status": status, "reason": reason, "budget": receipt["budget_at_end"],
                      "statuses": receipt["statuses"]}, indent=1))
    return rc


# ----------------------------------------------------------------------------- compare
def load_preds(path: str) -> dict[str, dict[str, Any]]:
    return {r["eval_unit_id"]: r for r in read_jsonl(path)}


def published_ci(root: str) -> dict[str, Any]:
    with open(os.path.join(root, CI_CSV), encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["corpus"] == "Codex" and row["auditor"] == "PAA" and row["backend"] == "S5":
                return {"recall": float(row["recall"]), "recall_ci": [float(row["recall_lo"]), float(row["recall_hi"])],
                        "fbr": float(row["fbr"]), "fbr_ci": [float(row["fbr_lo"]), float(row["fbr_hi"])],
                        "source": f"{CI_CSV} (paper Table 2 point estimates, Table 16 pair-bootstrap CIs)"}
    raise IntegrityError("Codex/PAA/S5 row not found in ci_estimates.csv")


def cmd_compare(a) -> int:
    root = resolve(a.artifact_root, "PAA_ARTIFACT_ROOT", "artifact_root")
    work = resolve(a.work, "PAA_WORK_DIR", "work")
    out = resolve(a.out, "PAA_OUT_DIR", "out")
    listed = files_listing(root)
    verify_files(root, [CODEX_MANIFEST, CI_CSV] + list(SHIPPED.values()), listed)
    _m, gold_path = stage_files(work, a.stage)
    rows = read_json(gold_path)
    ours = load_preds(os.path.join(out, "results.jsonl"))
    pop_path = os.path.join(work, "cell_population.json")
    pop = read_json(pop_path) if os.path.exists(pop_path) else None
    man = read_json(os.path.join(root, CODEX_MANIFEST))
    report: dict[str, Any] = {"adapter_version": ADAPTER_VERSION, "created_utc": utcnow(), "stage": a.stage,
                              "results": os.path.join(out, "results.jsonl"), "fidelity_class": "backbone-substituted"}
    for name, rel in SHIPPED.items():
        ref = load_preds(os.path.join(root, rel))
        report[f"vs_{name}"] = F.compare(rows, ours, ref, pop)
        report[f"{name}_full_corpus"] = {
            "full_view": F.confusion((m["gold"], F.pred_of(ref.get(m["eval_unit_id"]))) for m in man),
            "tool_call_view": F.confusion((m["gold"], F.pred_of(ref.get(m["eval_unit_id"])))
                                          for m in man if m["stratum"] in ("tool", "fc"))}
    pub = published_ci(root)
    ds = report["vs_paa_sonnet5"]["ours"]["full_view"]
    agree = report["vs_paa_sonnet5"]["agreement"]
    report["published_sonnet5_codex"] = pub
    report["checks"] = {
        "agreement_threshold_OPEN7": a.agreement_threshold,
        "agreement_meets_threshold": (agree["per_unit"] or 0) >= a.agreement_threshold,
        "recall_wilson_overlaps_published_ci": F.overlaps(tuple(ds["recall_wilson95"]), *pub["recall_ci"]),
        "fbr_wilson_overlaps_published_ci": F.overlaps(tuple(ds["fbr_wilson95"]), *pub["fbr_ci"]),
        "recall_wilson_contains_published_point": F.contains(tuple(ds["recall_wilson95"]), pub["recall"]),
        "fbr_wilson_contains_published_point": F.contains(tuple(ds["fbr_wilson95"]), pub["fbr"]),
        "missing_units": [r["eval_unit_id"] for r in rows if r["eval_unit_id"] not in ours],
        "units_with_transport_failures": [i for i, c in ours.items()
                                          if ((c.get("adapter") or {}).get("unit_transport_failures") or 0) > 0],
        "note": "n=60 Wilson intervals are wide; agreement with the shipped per-unit predictions is the primary signal",
    }
    report["usage"] = F.usage_from_certs(ours.values(), a.price_in_per_m, a.price_out_per_m)
    report["usage"]["price"] = PRICE_SNAPSHOT
    ledger = os.path.join(out, "adapter_ledger.jsonl")
    if os.path.exists(ledger):
        req, tok, usd = Ledger.totals(ledger)
        report["usage"]["ledger"] = {"requests_sent": req, "charged_tokens": tok, "charged_usd": round(usd, 4)}
    dest = a.json_out or os.path.join(out, f"fidelity_report_{a.stage}.json")
    write_json(dest, report)
    print(json.dumps({"report": dest, "ours": ds, "agreement": {k: agree[k] for k in agree if k != "disagreements"},
                      "checks": {k: v for k, v in report["checks"].items() if k != "note"},
                      "usage": report["usage"]}, indent=1))
    return 0


# ----------------------------------------------------------------------------- stage
def cmd_stage(a) -> int:
    """One capped command per stage: zero-cost prepare, the guarded run, then the zero-cost report."""
    out = os.path.abspath(a.out)
    work = os.path.join(out, "prepare")
    results = os.path.abspath(a.results_dir) if a.results_dir else os.path.join(out, "results")
    prep = argparse.Namespace(**vars(a))
    prep.work, prep.n_block, prep.n_pass, prep.tag = work, 30, 30, F.SAMPLE_TAG
    cmd_prepare(prep)
    run = argparse.Namespace(**vars(a))
    run.work, run.out = work, results
    rc = cmd_run(run)
    if os.path.exists(os.path.join(results, "results.jsonl")):
        cmp_ = argparse.Namespace(**vars(a))
        cmp_.work, cmp_.out, cmp_.json_out = work, results, None
        cmd_compare(cmp_)
    return rc


# ----------------------------------------------------------------------------- CLI
def _run_options(p) -> None:
    p.add_argument("--base-url", help="loopback URL; under the runner it must equal AUDITOR_GUARD_URL")
    p.add_argument("--cap-usd", type=float, required=True, help="client-side backstop; the guard cap is authoritative")
    p.add_argument("--cap-tokens", type=int, required=True)
    p.add_argument("--max-requests", type=int)
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--json-mode", action="store_true", help="send response_format json_object (deviation; off by default)")
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--timeout", type=int, default=900, help="per-request client timeout, seconds")
    p.add_argument("--tooldesc", choices=["patched", "released"], default="patched")
    p.add_argument("--no-contract", action="store_true")
    p.add_argument("--on-transport-error", choices=["abort", "fail-open"], default="abort")
    p.add_argument("--http-retries", type=int, default=2)
    p.add_argument("--dry-run-ollama", metavar="MODEL",
                   help="plumbing dry run (set automatically from AUDITOR_MODE/AUDITOR_BACKBONE under the runner)")
    p.add_argument("--direct-ollama", action="store_true",
                   help="debug only: talk to Ollama :11434 directly (no guard) with MODEL on the wire")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--artifact-root", help="audit-artifact-E593 root (or env PAA_ARTIFACT_ROOT)")
        p.add_argument("--work", help="prepare output dir with stage manifests (or env PAA_WORK_DIR)")
        p.add_argument("--price-in-per-m", type=float, default=PRICE_SNAPSHOT["input_usd_per_m"])
        p.add_argument("--price-out-per-m", type=float, default=PRICE_SNAPSHOT["output_usd_per_m"])
        p.add_argument("--max-tokens", type=int, default=8192, help="DeepSeek max_tokens per request (limit UNVERIFIED)")

    p = sub.add_parser("prepare", help="deterministic sample + zero-cost estimate")
    common(p)
    p.add_argument("--n-block", type=int, default=30)
    p.add_argument("--n-pass", type=int, default=30)
    p.add_argument("--tag", default=F.SAMPLE_TAG)
    p.set_defaults(fn=cmd_prepare)

    p = sub.add_parser("run", help="run one stage (needs prepare output in --work)")
    common(p)
    p.add_argument("--stage", required=True, choices=STAGES)
    p.add_argument("--out", help="results dir for this stage (or env PAA_OUT_DIR)")
    _run_options(p)
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("compare", help="fidelity report")
    common(p)
    p.add_argument("--stage", required=True, choices=STAGES)
    p.add_argument("--out", help="results dir of the stage (or env PAA_OUT_DIR)")
    p.add_argument("--json-out")
    p.add_argument("--agreement-threshold", type=float, default=0.80, help="OPEN-7 draft default")
    p.set_defaults(fn=cmd_compare)

    p = sub.add_parser("stage", help="prepare + run + compare in one process (the stages.json entry point)")
    common(p)
    p.add_argument("--stage", required=True, choices=STAGES)
    p.add_argument("--out", required=True, help="stage output dir (the runner passes {out_dir}/paa)")
    p.add_argument("--results-dir", help="resume into an earlier results dir instead of <out>/results")
    p.add_argument("--agreement-threshold", type=float, default=0.80)
    _run_options(p)
    p.set_defaults(fn=cmd_stage)
    return ap


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
