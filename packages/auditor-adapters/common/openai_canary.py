"""OpenAI route smoke: fixed, benign requests through the auditor guard, one set per model.

Run it only through ``deepseek_route.py run-stage`` (stage ``common/s1-openai-canary``);
it refuses to run unguarded.  For every chat model it sends a plain request
(``max_completion_tokens``) and a native tool-calling request with
``tool_choice=auto`` (``max_tokens`` for ordinary chat models, the only field
the AgentDojo-era artifacts send; ``max_completion_tokens`` for models named in
``--reasoning-models``).  For each model in ``--logprobs-models`` it adds one
request with ``logprobs=true, top_logprobs=5`` (the AttriGuard judge shape).
It sends one embeddings request with two short inputs to ``--embedding-model``.
Last, for each model in ``--probe-models`` it sends two wire probes whose answer is
not known in advance (RUN-PLAN-OPENAI.md open issue 3): the plain request with
``max_tokens`` instead of ``max_completion_tokens``, and the plain request with
``temperature=0``.  A probe may come back HTTP 400 (the field is rejected; an
upstream 400 is charged $0 by the guard, UNVERIFIED); probes are marked
``"probe": true`` and do not count toward the canary's own pass/fail.

It records status, served model, service tier, finish reason, tool-call shape,
logprobs shape, embedding dimensions and usage.  It stores no prompt text and
at most 80 characters of each reply.  Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from deepseek_route import require_guard  # noqa: E402

TOOL = {
    "type": "function",
    "function": {
        "name": "get_balance",
        "description": "Return the balance of a bank account.",
        "parameters": {
            "type": "object",
            "properties": {"account_id": {"type": "integer"}},
            "required": ["account_id"],
        },
    },
}
PLAIN = [
    {"role": "system", "content": "You are a terse assistant."},
    {"role": "user", "content": "Reply with exactly one word: pong"},
]
TOOL_MESSAGES = [{"role": "user", "content": "What is the balance of account 42? Use the tool."}]
LOGPROBS = [{"role": "user", "content": "Answer with one word, yes or no: is 2 greater than 1?"}]
EMBED_INPUTS = ["send_email(recipients = ['alice@example.com'])", "get_balance()"]


def _post(base_url: str, token: str, path: str, body: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=180) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read())
        except Exception:  # noqa: BLE001
            return error.code, {}


def _json_ok(text: object) -> bool:
    if not isinstance(text, str):
        return False
    try:
        json.loads(text)
        return True
    except json.JSONDecodeError:
        return False


def _chat_record(name: str, model: str, limit_field: str, status: int, payload: dict, started: float) -> dict:
    choice = (payload.get("choices") or [{}])[0] if isinstance(payload, dict) else {}
    message = choice.get("message") or {}
    tool_calls = message.get("tool_calls") or []
    content = message.get("content")
    logprobs = choice.get("logprobs") if isinstance(choice, dict) else None
    tokens = (logprobs or {}).get("content") or [] if isinstance(logprobs, dict) else []
    return {
        "request": name,
        "model": model,
        "limit_field": limit_field,
        "http_status": status,
        "error_code": (payload.get("error") or {}).get("code") if isinstance(payload, dict) else None,
        "model_echo": payload.get("model") if isinstance(payload, dict) else None,
        "service_tier": payload.get("service_tier") if isinstance(payload, dict) else None,
        "finish_reason": choice.get("finish_reason"),
        "tool_calls": [
            {"name": (call.get("function") or {}).get("name"),
             "arguments_json_ok": _json_ok((call.get("function") or {}).get("arguments"))}
            for call in tool_calls
        ],
        "logprobs_tokens": len(tokens),
        "top_logprobs_per_token": [len(t.get("top_logprobs") or []) for t in tokens[:4] if isinstance(t, dict)],
        "reply_prefix": content[:80] if isinstance(content, str) else None,
        "usage": payload.get("usage") if isinstance(payload, dict) else None,
        "latency_ms": int((time.monotonic() - started) * 1000),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--chat-models", nargs="+", required=True)
    parser.add_argument("--reasoning-models", nargs="*", default=[],
                        help="chat models that get max_completion_tokens on every request")
    parser.add_argument("--logprobs-models", nargs="*", default=[])
    parser.add_argument("--embedding-model", default=None)
    parser.add_argument("--probe-models", nargs="*", default=[],
                        help="chat models that get the max_tokens and temperature=0 wire probes (sent last)")
    args = parser.parse_args()
    if len(args.chat_models) > 6:
        parser.error("at most 6 chat models")
    unknown_probes = [model for model in args.probe_models if model not in args.chat_models]
    if unknown_probes:
        parser.error(f"--probe-models must be among --chat-models: {unknown_probes}")
    base_url, token = require_guard()
    results = []
    for model in args.chat_models:
        tool_field = "max_completion_tokens" if model in args.reasoning_models else "max_tokens"
        plan = [
            ("plain", {"messages": PLAIN, "max_completion_tokens": 16}, "max_completion_tokens"),
            ("tool_call", {"messages": TOOL_MESSAGES, "tools": [TOOL], "tool_choice": "auto", tool_field: 64},
             tool_field),
        ]
        if model in args.logprobs_models:
            plan.append(("logprobs", {"messages": LOGPROBS, "logprobs": True, "top_logprobs": 5,
                                      "max_completion_tokens": 4}, "max_completion_tokens"))
        for name, spec, limit_field in plan:
            started = time.monotonic()
            status, payload = _post(base_url, token, "/chat/completions", {"model": model, **spec})
            results.append(_chat_record(name, model, limit_field, status, payload, started))
    if args.embedding_model:
        started = time.monotonic()
        status, payload = _post(base_url, token, "/embeddings", {"model": args.embedding_model, "input": EMBED_INPUTS})
        data = payload.get("data") if isinstance(payload, dict) else None
        results.append({
            "request": "embeddings",
            "model": args.embedding_model,
            "http_status": status,
            "error_code": (payload.get("error") or {}).get("code") if isinstance(payload, dict) else None,
            "model_echo": payload.get("model") if isinstance(payload, dict) else None,
            "vectors": len(data) if isinstance(data, list) else None,
            "dimensions": len(data[0].get("embedding") or []) if isinstance(data, list) and data else None,
            "usage": payload.get("usage") if isinstance(payload, dict) else None,
            "latency_ms": int((time.monotonic() - started) * 1000),
        })
    for model in args.probe_models:
        probes = [
            ("probe_max_tokens", {"messages": PLAIN, "max_tokens": 16}, "max_tokens"),
            ("probe_temperature_0", {"messages": PLAIN, "temperature": 0, "max_completion_tokens": 16},
             "max_completion_tokens"),
        ]
        for name, spec, limit_field in probes:
            started = time.monotonic()
            status, payload = _post(base_url, token, "/chat/completions", {"model": model, **spec})
            record = _chat_record(name, model, limit_field, status, payload, started)
            record["probe"] = True
            record["answer"] = "field accepted" if status == 200 else (
                "field rejected (HTTP 400)" if status == 400 else f"inconclusive (HTTP {status})")
            results.append(record)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"schema": "auditor-openai-canary/v1", "results": results}, indent=2) + "\n",
                        encoding="utf-8")
    checked = [r for r in results if not r.get("probe")]
    ok = sum(1 for r in checked if r["http_status"] == 200)
    probes = {f"{r['model']}:{r['request']}": r["answer"] for r in results if r.get("probe")}
    print(json.dumps({"requests": len(results), "checked": len(checked), "ok": ok, "probes": probes}))
    return 0 if ok == len(checked) else 1


if __name__ == "__main__":
    sys.exit(main())
