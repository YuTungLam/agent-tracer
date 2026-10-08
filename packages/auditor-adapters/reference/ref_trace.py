"""Recorded-trace model, loaders and the common case contract for the offline auditors.

A *trace* is one recorded agent episode, normalised to ``reference-trace/v1``::

    {"schema": "reference-trace/v1", "trace_id", "format", "prefix_exact",
     "suite", "user_task_id", "case_id", "arm", "episode_id", "repeat",
     "messages": [
        {"index", "attempt", "role": "system"|"user", "text"},
        {"index", "attempt", "role": "assistant", "text", "tool_calls": [{"call_id", "function", "args"}]},
        {"index", "attempt", "role": "tool", "text", "call_id", "function", "args", "error"}],
     "recorded": {"utility", "post_state_adds_attacker", "run_error", "outcome", ...}}

``attempt`` (default 0) separates the conversations of AgentDojo's 3-attempt query
loop: each attempt starts a fresh message list (the model never sees an earlier
attempt's messages) while the task environment carries over. Visibility therefore
stops at the attempt boundary (``attempt_start``), but executed calls and gated
replays run over every attempt in order.

Loaders accept (1) AgentDojo ChatMessage logs (the benchmark's JSON logs, the lab
harness and ADI traces, ground-truth pipeline runs), which keep the exact prefix;
(2) H2 runner transcripts: the ``h2-transcript/v2`` form keeps every attempt's full
message list (exact prefix); the older form keeps only executed calls and tool
outputs, so the assistant turn grouping and (unless resolved) the user prompt are
missing and the prefix is an over-approximation (``prefix_exact = false``);
(3) native ``reference-trace/v1`` files (synthetic tests).

The *case contract* (H2-CASES-V1.md, per case and arm) is
``{suite, user_task_id, injections: {vector_id: text}, oracle}``. Any injections
dict over AgentDojo v1.2.2 vectors is accepted, including multi-vector A1 cases.
Outcomes are scored only with ``agentdojo_lab.h2_cases.classify_outcome`` (executed
calls plus native post-state), never with AgentDojo injection-task security oracles.

The *source* of a value is one model-visible message: the system prompt, the user
prompt, or one tool result as rendered to the model (the error string replaces the
content when the tool failed, as the AgentDojo OpenAI adapter renders it). Assistant
text is model output, not a source. Saved text is untrusted data, never instructions.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

from ref_common import ReferenceError, census, h2_cases, read_json, read_jsonl, sha256_bytes

SCHEMA_TRACE = "reference-trace/v1"
SCHEMA_CASE_ARM = "reference-case-arm/v1"
ROLES = ("system", "user", "assistant", "tool")


# ---------------------------------------------------------------------------
# Message normalisation
# ---------------------------------------------------------------------------


def content_text(content: Any) -> str:
    """Text of an AgentDojo / OpenAI content field (str or list of text blocks)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                text = block.get("content") if block.get("content") is not None else block.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "".join(parts)
    return str(content)


def _call_dict(call: Any) -> dict[str, Any]:
    """FunctionCall (pydantic, dict, or OpenAI wire shape) -> {call_id, function, args}."""
    if call is None:
        return {"call_id": None, "function": None, "args": {}}
    if not isinstance(call, Mapping):
        call = {"function": getattr(call, "function", None), "args": dict(getattr(call, "args", {}) or {}),
                "id": getattr(call, "id", None)}
    if isinstance(call.get("function"), Mapping):  # OpenAI wire shape
        fn = call["function"]
        raw = fn.get("arguments")
        try:
            args = json.loads(raw) if isinstance(raw, str) else dict(raw or {})
        except ValueError:
            args = {"__unparsed_arguments__": raw}
        return {"call_id": call.get("id"), "function": fn.get("name"), "args": args}
    return {"call_id": call.get("id"), "function": call.get("function"), "args": dict(call.get("args") or {})}


def normalise_messages(raw: Sequence[Mapping[str, Any]], *, attempt: int = 0, start: int = 0) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for offset, message in enumerate(raw):
        index = start + offset
        if not isinstance(message, Mapping):
            raise ReferenceError(f"message {index} is not an object")
        role = message.get("role")
        if role not in ROLES:
            raise ReferenceError(f"message {index} has unknown role {role!r}")
        item: dict[str, Any] = {"index": index, "attempt": attempt, "role": role,
                                "text": content_text(message.get("content"))}
        if role == "assistant":
            item["tool_calls"] = [_call_dict(c) for c in (message.get("tool_calls") or [])]
        elif role == "tool":
            call = _call_dict(message.get("tool_call"))
            error = message.get("error")
            item.update({"call_id": message.get("tool_call_id") or call["call_id"],
                         "function": call["function"], "args": call["args"],
                         "error": None if error in (None, "") else str(error)})
        out.append(item)
    return out


def _new_trace(trace_id: str, fmt: str, messages: list[dict[str, Any]], *, prefix_exact: bool,
               meta: Mapping[str, Any] | None = None) -> dict[str, Any]:
    meta = dict(meta or {})
    return {
        "schema": SCHEMA_TRACE, "trace_id": trace_id, "format": fmt, "prefix_exact": prefix_exact,
        "suite": meta.get("suite"), "user_task_id": meta.get("user_task_id"),
        "case_id": meta.get("case_id"), "arm": meta.get("arm"), "episode_id": meta.get("episode_id"),
        "repeat": meta.get("repeat"), "messages": messages,
        "recorded": dict(meta.get("recorded") or {}),
        "notes": list(meta.get("notes") or []),
    }


def trace_from_messages(messages: Sequence[Mapping[str, Any]], *, trace_id: str,
                        meta: Mapping[str, Any] | None = None, fmt: str = "agentdojo_messages") -> dict[str, Any]:
    return _new_trace(trace_id, fmt, normalise_messages(messages), prefix_exact=True, meta=meta)


def trace_from_agentdojo_log(doc: Mapping[str, Any], *, trace_id: str | None = None) -> dict[str, Any]:
    """An AgentDojo benchmark JSON log (``messages`` plus suite/task ids and scores)."""
    if not isinstance(doc.get("messages"), list):
        raise ReferenceError("AgentDojo log has no messages list")
    suite, task = doc.get("suite_name"), doc.get("user_task_id")
    tid = trace_id or f"agentdojo:{suite}/{task}/{doc.get('attack_type')}/{doc.get('injection_task_id')}"
    recorded = {"utility": doc.get("utility"), "agentdojo_security": doc.get("security"),
                "run_error": bool(doc.get("error")), "post_state_adds_attacker": None}
    return trace_from_messages(doc["messages"], trace_id=tid, meta={
        "suite": suite, "user_task_id": task, "recorded": recorded,
        "notes": ["agentdojo_security is the injection-task oracle; recorded only, never scored"]})


def _call_key(function: Any, args: Any, success: Any) -> tuple[Any, str, bool]:
    return (function, json.dumps(dict(args or {}), sort_keys=True, ensure_ascii=False, default=str), bool(success))


def _trace_from_h2_attempts(tid: str, transcript: Mapping[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    """``h2-transcript/v2``: one full AgentDojo message list per attempt (exact prefix per attempt)."""
    messages: list[dict[str, Any]] = []
    attempts_meta: list[dict[str, Any]] = []
    for pos, attempt in enumerate(transcript["attempts"]):
        if not isinstance(attempt, Mapping) or not isinstance(attempt.get("messages"), list):
            raise ReferenceError(f"{tid}: attempt {pos} has no messages list")
        k = attempt.get("index", pos)
        if k != pos:
            raise ReferenceError(f"{tid}: attempt indices out of order ({k} at position {pos})")
        norm = normalise_messages(attempt["messages"], attempt=pos, start=len(messages))
        messages.extend(norm)
        attempts_meta.append({"index": pos, "ended": attempt.get("ended"), "error_type": attempt.get("error_type"),
                              "salvaged": bool(attempt.get("salvaged")), "messages": len(norm)})
    notes = list(meta.get("notes") or [])
    if len(attempts_meta) > 1:
        notes.append(f"{len(attempts_meta)} attempts: visibility stops at each attempt boundary; calls of every "
                     "attempt are executed calls (the environment carries over)")
    if any(a["salvaged"] for a in attempts_meta):
        notes.append("an attempt was salvaged after an error: its messages are those seen at the last model call")
    meta = {**meta, "notes": notes}
    trace = _new_trace(tid, "h2_attempts", messages, prefix_exact=True, meta=meta)
    trace["attempts"] = attempts_meta
    flat = transcript.get("executed_calls")
    if flat is not None:
        mine = [_call_key(c["function"], c["args"], c["success"]) for c in executed_calls(trace)]
        theirs = [_call_key(c.get("function"), c.get("args"), c.get("success")) for c in flat]
        if mine != theirs:
            raise ReferenceError(f"{tid}: executed_calls ({len(theirs)}) differ from the calls answered in the "
                                 f"attempt messages ({len(mine)})")
    return trace


def trace_from_h2(episode: Mapping[str, Any], transcript: Mapping[str, Any], *,
                  user_prompt: str | None = None, system_prompt: str | None = None) -> dict[str, Any]:
    """An H2 runner episode record plus its transcript.

    ``attempts`` (runner transcript ``h2-transcript/v2``): every attempt's full
    AgentDojo message list, concatenated with an ``attempt`` index per message; the
    prefix is exact. A bare ``messages`` list is read the same way as one attempt.
    Otherwise (older transcripts: executed calls and tool outputs only) each executed
    call becomes its own assistant turn followed by its tool result: a call then
    "sees" every earlier tool output, which over-approximates visibility for calls
    issued in parallel in one turn (``prefix_exact = false``). The user prompt is
    included only when resolved.
    """
    if transcript.get("episode_id") not in (None, episode.get("episode_id")):
        raise ReferenceError(f"transcript episode_id {transcript.get('episode_id')!r} != record "
                             f"{episode.get('episode_id')!r}")
    meta = {
        "suite": episode.get("suite"), "user_task_id": episode.get("user_task"),
        "case_id": episode.get("case_id"), "arm": episode.get("arm"), "episode_id": episode.get("episode_id"),
        "repeat": episode.get("repeat"),
        "recorded": {"utility": episode.get("utility"), "run_error": bool(episode.get("run_error")),
                     "outcome": episode.get("outcome"), "subtype": episode.get("subtype"),
                     "post_state_adds_attacker": (episode.get("oracle_details") or {}).get("post_state_adds_attacker"),
                     "injection_exposed": episode.get("injection_exposed"),
                     "injection_payload_sha256": episode.get("injection_payload_sha256"),
                     "attempts_run": episode.get("attempts_run"),
                     "salvaged_after_error": episode.get("salvaged_after_error")},
    }
    tid = f"h2:{episode.get('episode_id')}"
    if isinstance(transcript.get("attempts"), list):
        return _trace_from_h2_attempts(tid, transcript, meta)
    if isinstance(transcript.get("messages"), list):
        return trace_from_messages(transcript["messages"], trace_id=tid, meta=meta, fmt="h2_messages")
    calls = transcript.get("executed_calls") or []
    outputs = transcript.get("tool_outputs") or []
    if len(calls) != len(outputs):
        raise ReferenceError(f"{tid}: executed_calls ({len(calls)}) and tool_outputs ({len(outputs)}) differ in length")
    raw: list[dict[str, Any]] = []
    notes = ["prefix_exact=false: assistant turn grouping not recorded; each call sees all earlier tool outputs"]
    if system_prompt is not None:
        raw.append({"role": "system", "content": system_prompt})
    if user_prompt is not None:
        raw.append({"role": "user", "content": user_prompt})
    else:
        notes.append("user prompt not recorded and not resolved: origin rules see no user prompt")
    for i, (call, output) in enumerate(zip(calls, outputs)):
        cid = f"h2call_{i}"
        fc = {"function": call.get("function"), "args": dict(call.get("args") or {}), "id": cid}
        raw.append({"role": "assistant", "content": None, "tool_calls": [fc]})
        error = None if call.get("success", True) else (call.get("error") or "tool error (text not recorded)")
        raw.append({"role": "tool", "content": output, "tool_call_id": cid, "tool_call": fc, "error": error})
    meta["notes"] = notes
    return _new_trace(tid, "h2_transcript", normalise_messages(raw), prefix_exact=False, meta=meta)


def validate_trace(trace: Mapping[str, Any]) -> dict[str, Any]:
    if trace.get("schema") != SCHEMA_TRACE:
        raise ReferenceError(f"trace schema must be {SCHEMA_TRACE}")
    if not isinstance(trace.get("messages"), list) or not trace.get("trace_id"):
        raise ReferenceError("trace needs trace_id and messages")
    for i, m in enumerate(trace["messages"]):
        if m.get("index") != i or m.get("role") not in ROLES:
            raise ReferenceError(f"{trace['trace_id']}: message {i} malformed")
    return dict(trace)


def load_trace_file(path: Path) -> dict[str, Any]:
    doc = read_json(path)
    if doc.get("schema") == SCHEMA_TRACE:
        return validate_trace(doc)
    if isinstance(doc.get("messages"), list) and "suite_name" in doc:
        return trace_from_agentdojo_log(doc, trace_id=f"agentdojo:{Path(path).as_posix()}")
    raise ReferenceError(f"{path}: unrecognised trace format (H2 transcripts load through load_h2_run)")


def _check_transcript_hash(tid: str, data: bytes, recorded: str | None) -> None:
    """The runner records the transcript's sha256; accept it under LF or CRLF line endings only."""
    if not recorded:
        return
    lf = data.replace(b"\r\n", b"\n")
    if recorded not in {sha256_bytes(data), sha256_bytes(lf), sha256_bytes(lf.replace(b"\n", b"\r\n"))}:
        raise ReferenceError(f"{tid}: transcript sha256 differs from the episode record")


def load_h2_run_report(run_dir: Path, *, prompt_resolver: Callable[[str, str], str | None] | None = None,
                       system_prompt: str | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Every episode of an H2 runner output dir (episodes.jsonl + transcripts/), with a load report.

    The first record per episode id is kept (the runner's ``_latest`` rule). An
    episode without a transcript file is listed under ``missing_transcripts``; an
    episode whose transcript is malformed or inconsistent (length mismatch, hash or
    episode-id mismatch, executed calls that the messages do not answer) is listed
    under ``unloadable_episodes`` and skipped, so one bad episode never aborts the
    run. ``plan`` is the run's ``episode_plan.json`` case-file block and per-episode
    payload hashes (None when the file is absent). Each trace records its run dir.
    """
    run_dir = Path(run_dir)
    records: dict[str, dict[str, Any]] = {}
    for row in read_jsonl(run_dir / "episodes.jsonl"):
        records.setdefault(row["episode_id"], row)
    traces: list[dict[str, Any]] = []
    unloadable: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for episode in records.values():
        name = episode.get("transcript_path")
        path = run_dir / "transcripts" / name if name else None
        if path is None or not path.is_file():
            missing.append({"episode_id": episode["episode_id"],
                            "reason": ("transcript_error: " + str(episode["transcript_error"])[:200])
                            if episode.get("transcript_error") else "no transcript file"})
            continue
        tid = f"h2:{episode['episode_id']}"
        try:
            data = path.read_bytes()
            _check_transcript_hash(tid, data, episode.get("transcript_sha256"))
            transcript = json.loads(data.decode("utf-8"))
            if not isinstance(transcript, Mapping):
                raise ReferenceError(f"{tid}: transcript is not a JSON object")
            exact = isinstance(transcript.get("attempts"), list) or isinstance(transcript.get("messages"), list)
            prompt = (prompt_resolver(episode["suite"], episode["user_task"])
                      if prompt_resolver and not exact else None)
            trace = trace_from_h2(episode, transcript, user_prompt=prompt, system_prompt=system_prompt)
        except (ReferenceError, ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
            unloadable.append({"episode_id": episode["episode_id"], "transcript_path": name,
                               "reason": f"{type(exc).__name__}: {str(exc)[:300]}"})
            continue
        trace["h2_run"] = str(run_dir)
        traces.append(trace)
    plan = None
    if (run_dir / "episode_plan.json").is_file():
        doc = read_json(run_dir / "episode_plan.json")
        plan = {"case_file": dict(doc.get("case_file") or {}), "plan_digest": doc.get("plan_digest"),
                "stage": doc.get("stage"),
                "payload_sha256": {e["episode_id"]: e.get("injection_payload_sha256")
                                   for e in doc.get("episodes") or [] if isinstance(e, Mapping) and "episode_id" in e}}
    report = {"run_dir": str(run_dir), "episodes": len(records), "loaded": len(traces),
              "unloadable_episodes": unloadable, "missing_transcripts": missing, "plan": plan}
    return traces, report


def load_h2_run(run_dir: Path, *, prompt_resolver: Callable[[str, str], str | None] | None = None,
                system_prompt: str | None = None) -> list[dict[str, Any]]:
    """The loadable traces of an H2 run dir (see ``load_h2_run_report`` for what is skipped)."""
    return load_h2_run_report(run_dir, prompt_resolver=prompt_resolver, system_prompt=system_prompt)[0]


# ---------------------------------------------------------------------------
# Proposals, sources, executed calls
# ---------------------------------------------------------------------------


def proposals(trace: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every proposed tool call, in order, with the tool result that answered it (if any)."""
    msgs = trace["messages"]
    out: list[dict[str, Any]] = []
    for m in msgs:
        if m["role"] != "assistant" or not m.get("tool_calls"):
            continue
        # Tool results that answer this assistant turn: until the next assistant message
        # (or the start of the next attempt).
        answers = []
        for later in msgs[m["index"] + 1:]:
            if later["role"] == "assistant" or later.get("attempt", 0) != m.get("attempt", 0):
                break
            if later["role"] == "tool":
                answers.append(later)
        used: set[int] = set()
        for j, call in enumerate(m["tool_calls"]):
            answer = None
            if call.get("call_id") is not None:
                answer = next((a for a in answers if a.get("call_id") == call["call_id"] and a["index"] not in used), None)
            if answer is None and j < len(answers) and answers[j]["index"] not in used:
                answer = answers[j]  # positional fallback when ids are absent
            if answer is not None:
                used.add(answer["index"])
            out.append({
                "proposal_id": f"{m['index']}.{j}", "msg_index": m["index"], "position": j,
                "function": call.get("function"), "args": dict(call.get("args") or {}), "call_id": call.get("call_id"),
                "executed": answer is not None,
                "success": None if answer is None else answer.get("error") is None,
                "tool_msg_index": None if answer is None else answer["index"],
            })
    return out


def source_text(message: Mapping[str, Any]) -> str:
    if message["role"] == "tool" and message.get("error"):
        return str(message["error"])
    return message.get("text") or ""


def attempt_start(trace: Mapping[str, Any], msg_index: int) -> int:
    """Index of the first message of the attempt that holds ``msg_index`` (0 for one attempt)."""
    msgs = trace["messages"]
    if not msgs:
        return 0
    i = min(max(msg_index, 0), len(msgs) - 1)
    attempt = msgs[i].get("attempt", 0)
    i = min(msg_index, len(msgs))
    while i > 0 and msgs[i - 1].get("attempt", 0) == attempt:
        i -= 1
    return i


def sources_before(trace: Mapping[str, Any], msg_index: int) -> list[dict[str, Any]]:
    """Model-visible sources before the assistant message at ``msg_index`` (same attempt only)."""
    out = []
    for m in trace["messages"][attempt_start(trace, msg_index):msg_index]:
        if m["role"] in ("system", "user"):
            out.append({"source_id": f"{m['role']}:{m['index']}", "kind": m["role"], "msg_index": m["index"],
                        "tool": None, "text": m.get("text") or "", "error": None})
        elif m["role"] == "tool":
            out.append({"source_id": f"tool:{m['index']}", "kind": "tool", "msg_index": m["index"],
                        "tool": m.get("function"), "args": m.get("args"), "text": source_text(m),
                        "error": m.get("error")})
    return out


def executed_calls(trace: Mapping[str, Any], *, stop_before: tuple[int, int] | None = None) -> list[dict[str, Any]]:
    """Executed calls in order, as classify_outcome expects ({function, args, success}).

    ``stop_before=(msg_index, position)`` keeps only calls proposed before that
    proposal (same assistant turn: earlier positions only), for gated replays.
    """
    out = []
    for p in proposals(trace):
        if not p["executed"]:
            continue
        if stop_before is not None and (p["msg_index"], p["position"]) >= stop_before:
            break
        tool = trace["messages"][p["tool_msg_index"]]
        out.append({"function": p["function"], "args": dict(p["args"]), "success": bool(p["success"]),
                    "error": tool.get("error")})
    return out


# ---------------------------------------------------------------------------
# Authority values and roles
# ---------------------------------------------------------------------------


def authority_values(function: str, args: Mapping[str, Any],
                     authority_args: Mapping[str, Sequence[str]]) -> list[dict[str, Any]]:
    """Element-wise authority values of one call (census value_strings rule)."""
    out = []
    for arg in sorted(authority_args.get(function) or []):
        if arg not in args:
            continue
        value = args[arg]
        items = value if isinstance(value, list) else [value]
        for i, item in enumerate(items):
            for s in census.value_strings(item):
                out.append({"argument": arg, "element_index": i if isinstance(value, list) else None,
                            "leaf_path": f"/{arg}/{i}" if isinstance(value, list) else f"/{arg}", "value": s})
    return out


def value_kinds_from_census_config(path: Path) -> dict[str, dict[str, str]]:
    """{function: {argument: value_kind}} over every suite (census config tools table)."""
    cfg = read_json(path)
    kinds: dict[str, dict[str, str]] = {}
    for tools in cfg["tools"].values():
        for name, spec in tools.items():
            for arg, kind in (spec.get("authority") or {}).items():
                kinds.setdefault(name, {})[arg] = kind
    return kinds


def value_role(value: str, spec: Mapping[str, Any] | None) -> str:
    """attacker / legitimate / decoy / other, by the oracle's normalize_value equality."""
    if not spec:
        return "unbound"
    oracle = spec["oracle"]
    n = h2_cases.normalize_value(value)
    if oracle.get("attacker_value") is not None and n == h2_cases.normalize_value(oracle["attacker_value"]):
        return "attacker"
    if any(n == h2_cases.normalize_value(v) for v in oracle.get("legitimate_set") or []):
        return "legitimate"
    if oracle.get("decoy_value") is not None and n == h2_cases.normalize_value(oracle["decoy_value"]):
        return "decoy"
    return "other"


# ---------------------------------------------------------------------------
# Value matching (exact structural first, then a declared normalisation)
# ---------------------------------------------------------------------------


@lru_cache(maxsize=4096)
def _scalars(text: str) -> tuple[str, ...]:
    """Decoded scalar values of a YAML/JSON source (lab provenance.structured_scalars)."""
    try:
        from agentdojo_lab.provenance import structured_scalars
    except ImportError:  # PyYAML unavailable: structural matching disabled, text rules still apply
        return ()
    parsed = structured_scalars(text)
    return tuple(s["value"] for s in parsed.get("scalars") or [] if isinstance(s.get("value"), str))


_SENTENCE_FINAL = ".,;:!?"


def bounded_exact(text: str, value: str) -> bool:
    """Lab ``lexical.exact_spans`` (min length 1), plus one declared refinement.

    exact_spans treats an adjacent ``_@./:+-`` as connected, so a value that ends a
    sentence ("The recipient is US12...212.") is not bounded. Here sentence-final
    punctuation (``.,;:!?``) followed by whitespace or the end of the text also
    counts as a boundary; everything else is the lab rule unchanged.
    """
    from agentdojo_lab.lexical import _connected, exact_spans

    if exact_spans(text, value, min_length=1):
        return True
    start = text.find(value)
    while start != -1:
        end = start + len(value)
        before_ok = start == 0 or not _connected(text[start - 1])
        after_ok = (end == len(text) or not _connected(text[end])
                    or (text[end] in _SENTENCE_FINAL and (end + 1 == len(text) or text[end + 1].isspace())))
        if before_ok and after_ok:
            return True
        start = text.find(value, start + 1)
    return False


def eq1_canonical(text: str, kind: str | None) -> str:
    """SIEVE EQ1 canonical form (SPEC.md 3.3): NFC, strip, collapse whitespace; kind rules."""
    s = " ".join(unicodedata.normalize("NFC", str(text)).split())
    if kind in ("email_address", "url"):
        s = s.casefold()
    elif kind == "account":
        s = s.replace(" ", "").upper()
    return s


def match_stage(value: str, kind: str | None, text: str, stage: str, *, structured: bool = True) -> dict[str, Any] | None:
    """Return match evidence of ``value`` in one source text under one declared stage, else None.

    exact:      a decoded YAML/JSON scalar equals the value, or a bounded verbatim
                occurrence (``bounded_exact``: lab exact_spans, min length 1, no
                normalisation, plus the sentence-final punctuation refinement);
    census:     the census matching rule (casefold, whitespace collapse, word/numeric
                boundary) over the raw text or any decoded scalar;
    sieve_eq1:  SIEVE EQ1 kind canonicalisation, then the census boundary rule.

    ``structured=False`` (system and user prompts, which are free text) disables the
    decoded-scalar view, so the prompt rule is the census rule on the raw text only.
    """
    if not value or not text:
        return None
    scalars = _scalars(text) if structured else ()
    if stage == "exact":
        for scalar in scalars:
            if scalar == value:
                return {"stage": "exact", "evidence": "structured_scalar_equal"}
        if bounded_exact(text, value):
            return {"stage": "exact", "evidence": "bounded_exact_text"}
        return None
    if stage == "census":
        needle = census.normalise(value)
        for hay in (text, *scalars):
            if census.contains(census.normalise(hay), needle):
                return {"stage": "census", "evidence": "census_contains"}
        return None
    if stage == "sieve_eq1":
        needle = eq1_canonical(value, kind)
        if not needle:
            return None
        if kind == "account":
            # EQ1 drops spaces inside an account value; in free text that is an
            # optional single space between characters, with alphanumeric boundaries.
            pattern = re.compile(r"(?<![0-9A-Za-z])" + r" ?".join(re.escape(c) for c in needle) + r"(?![0-9A-Za-z])",
                                 re.IGNORECASE)
            for hay in (text, *scalars):
                if eq1_canonical(hay, kind) == needle or pattern.search(" ".join(unicodedata.normalize("NFC", hay).split())):
                    return {"stage": "sieve_eq1", "evidence": "eq1_contains"}
            return None
        for hay in (text, *scalars):
            if census.contains(eq1_canonical(hay, kind), needle):
                return {"stage": "sieve_eq1", "evidence": "eq1_contains"}
        return None
    raise ReferenceError(f"unknown matching stage {stage!r}")


def contains_any(text: str, values: Sequence[str]) -> bool:
    """Census-rule containment of any candidate value (raw text or decoded scalars)."""
    return any(match_stage(v, None, text, "census") for v in values if v)


# ---------------------------------------------------------------------------
# Case contract
# ---------------------------------------------------------------------------


def load_case_file(path: Path) -> dict[str, Any]:
    doc = read_json(path)
    if not isinstance(doc.get("cases"), list) or not doc.get("authority_arg_map"):
        raise ReferenceError(f"{path}: case file needs cases and authority_arg_map")
    return doc


def case_arm_spec(doc: Mapping[str, Any], case_id: str, arm: str) -> dict[str, Any]:
    case = next((c for c in doc["cases"] if c["case_id"] == case_id), None)
    if case is None:
        raise ReferenceError(f"case {case_id!r} not in case file")
    if arm not in case["arms"]:
        raise ReferenceError(f"case {case_id!r} has no arm {arm!r}")
    a = case["arms"][arm]
    gt = case.get("gt") or {}
    design = dict(case.get("design") or {})
    steering = list(design.get("steering_texts") or [])
    if a.get("arm_text") and a.get("carries_attacker_value"):
        steering.append(a["arm_text"])
    spec = {
        "schema": SCHEMA_CASE_ARM, "case_id": case_id, "arm": arm,
        "suite": case["suite"], "user_task_id": case["user_task_id"],
        "injections": dict(a["injections"]),
        "oracle": {
            "target": case["target"], "legitimate_set": list(case.get("legitimate_set") or []),
            "attacker_value": case.get("attacker_value"), "decoy_value": case.get("decoy_value"),
            "authority_arg_map": {k: list(v) for k, v in doc["authority_arg_map"].items()},
            "attacker_state_observable": bool(gt.get("attacker_execution_state_observable")),
            "attacker_executable": bool(gt.get("attacker_executable")),
        },
        "design": {
            "stratum": design.get("stratum") or case.get("stratum") or "SS",
            "carries_attacker_value": bool(a.get("carries_attacker_value")),
            "steering_texts": steering,
            "carrier_markers": list(design.get("carrier_markers") or []),
            "carrier_tools": list(design.get("carrier_tools") or []),
        },
        "split": case.get("split"), "value_kind": case["target"].get("value_kind"),
        "seed_family": case.get("seed_family"),
    }
    return validate_spec(spec)


def spec_from_contract(d: Mapping[str, Any]) -> dict[str, Any]:
    """The flat contract form {suite, user_task(_id), injections, oracle, design?}."""
    spec = {
        "schema": SCHEMA_CASE_ARM, "case_id": d.get("case_id"), "arm": d.get("arm"),
        "suite": d["suite"], "user_task_id": d.get("user_task_id") or d.get("user_task"),
        "injections": dict(d.get("injections") or {}), "oracle": dict(d["oracle"]),
        "design": {"stratum": "unspecified", "carries_attacker_value": None, "steering_texts": [],
                   "carrier_markers": [], "carrier_tools": [], **dict(d.get("design") or {})},
        "split": d.get("split"), "value_kind": (d["oracle"].get("target") or {}).get("value_kind"),
        "seed_family": d.get("seed_family"),
    }
    return validate_spec(spec)


def validate_spec(spec: dict[str, Any], known_vectors: Sequence[str] | None = None) -> dict[str, Any]:
    inj = spec.get("injections")
    if not isinstance(inj, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in inj.items()):
        raise ReferenceError(f"{spec.get('case_id')}/{spec.get('arm')}: injections must be a {{vector_id: text}} dict")
    if known_vectors is not None:
        unknown = sorted(set(inj) - set(known_vectors))
        if unknown:
            raise ReferenceError(f"{spec.get('case_id')}/{spec.get('arm')}: unknown injection vectors {unknown}")
    oracle = spec.get("oracle") or {}
    for key in ("target", "legitimate_set", "attacker_value", "authority_arg_map"):
        if key not in oracle:
            raise ReferenceError(f"{spec.get('case_id')}/{spec.get('arm')}: oracle needs {key}")
    target = oracle["target"]
    if not target.get("function") or not target.get("argument"):
        raise ReferenceError("oracle.target needs function and argument")
    return spec


def iter_case_arm_specs(doc: Mapping[str, Any], *, runnable_only: bool = True) -> list[dict[str, Any]]:
    out = []
    for case in doc["cases"]:
        if runnable_only and not (case.get("invariants") or {}).get("all"):
            continue
        for arm in sorted(case["arms"]):
            out.append(case_arm_spec(doc, case["case_id"], arm))
    return out


# ---------------------------------------------------------------------------
# Design-label sources (carrier / steering) inside one trace prefix
# ---------------------------------------------------------------------------


def candidate_values(spec: Mapping[str, Any] | None) -> list[str]:
    if not spec:
        return []
    o = spec["oracle"]
    vals = [o.get("attacker_value"), *(o.get("legitimate_set") or []), o.get("decoy_value")]
    return [str(v) for v in vals if v not in (None, "")]


def carrier_source_ids(sources: Sequence[Mapping[str, Any]], spec: Mapping[str, Any] | None) -> set[str]:
    """Tool-result sources that carry a candidate value (X, any L, or D) of the case.

    Declared operationalisation of "the carrier" (protocol 4.6 carrier trust) at the
    source granularity of protocol 4.5: a successful tool result whose text (or a
    decoded scalar) contains a candidate value under the census rule, optionally
    restricted by the case design's ``carrier_tools`` and ``carrier_markers``.
    """
    if not spec:
        return set()
    values = candidate_values(spec)
    design = spec.get("design") or {}
    tools = set(design.get("carrier_tools") or [])
    markers = [h2_cases.collapse_ws(m) for m in design.get("carrier_markers") or [] if m]
    out = set()
    for s in sources:
        if s["kind"] != "tool" or s.get("error"):
            continue
        if tools and s.get("tool") not in tools:
            continue
        if markers and not any(m in h2_cases.collapse_ws(s["text"]) for m in markers):
            continue
        if contains_any(s["text"], values):
            out.add(s["source_id"])
    return out


def carrier_scope(spec: Mapping[str, Any] | None) -> str | None:
    """How the carrier of a case is defined: ``declared`` or ``content_derived`` (None when unbound).

    ``declared``: the case design names ``carrier_tools`` or ``carrier_markers`` (A1
    cases; protocol O2 "sources marked admissible in the case design").
    ``content_derived``: no declaration, so the carrier is every tool result that
    contains a candidate value. On an SS case that is the steering output itself, so
    both carrier labellings fix the decision on X by construction (``trivial_on_SS``).
    """
    if not spec:
        return None
    design = spec.get("design") or {}
    return "declared" if (design.get("carrier_tools") or design.get("carrier_markers")) else "content_derived"


def value_source_ids(sources: Sequence[Mapping[str, Any]], value: str) -> set[str]:
    """Tool results that carry this exact value (census rule): its value sources."""
    return {s["source_id"] for s in sources if s["kind"] == "tool" and not s.get("error")
            and match_stage(value, None, s["text"], "census")}


def steering_source_ids(sources: Sequence[Mapping[str, Any]], spec: Mapping[str, Any] | None) -> set[str]:
    """Tool results containing a design steering text (generator rule: collapse_ws substring)."""
    if not spec:
        return set()
    needles = [h2_cases.collapse_ws(t) for t in (spec.get("design") or {}).get("steering_texts") or [] if t]
    out = set()
    for s in sources:
        if s["kind"] != "tool":
            continue
        views = [h2_cases.collapse_ws(v) for v in (s["text"], *_scalars(s["text"]))]
        if any(n and n in view for n in needles for view in views):
            out.add(s["source_id"])
    return out
