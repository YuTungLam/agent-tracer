"""Route canary: a few fixed, benign chat requests through the auditor guard.

Run it only through ``deepseek_route.py run-stage`` (it refuses to run
unguarded).  It checks that the route accepts the lab wire shape: a plain
request and a native tool-calling request with ``tool_choice=auto``.  It
records status, finish reason, tool-call shape and usage; it stores no prompt
text and at most 80 characters of each reply.

``--client openai`` uses the ``openai`` SDK from the current venv (the way the
artifacts call the model); ``--client urllib`` needs only the standard library.
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
REQUESTS = [
    {
        "name": "plain",
        "messages": [
            {"role": "system", "content": "You are a terse assistant."},
            {"role": "user", "content": "Reply with exactly one word: pong"},
        ],
        "max_tokens": 16,
    },
    {
        "name": "tool_call",
        "messages": [{"role": "user", "content": "What is the balance of account 42? Use the tool."}],
        "tools": [TOOL],
        "tool_choice": "auto",
        "max_tokens": 64,
    },
]


def _via_urllib(base_url: str, token: str, body: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
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


def _via_openai(base_url: str, token: str, body: dict) -> tuple[int, dict]:
    import openai  # imported lazily: only the artifact venvs have it

    client = openai.OpenAI(base_url=base_url, api_key=token, max_retries=0, timeout=180)
    kwargs = {k: v for k, v in body.items() if k not in ("model",)}
    try:
        completion = client.chat.completions.create(model=body["model"], **kwargs)
        return 200, completion.model_dump(mode="json")
    except openai.APIStatusError as error:
        try:
            return error.status_code, error.response.json()
        except Exception:  # noqa: BLE001
            return error.status_code, {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--requests", type=int, default=2, help="1-10; cycles through the fixed requests")
    parser.add_argument("--model", default="deepseek-flash")
    parser.add_argument("--client", choices=("urllib", "openai"), default="urllib")
    args = parser.parse_args()
    if not 1 <= args.requests <= 10:
        parser.error("--requests must be between 1 and 10")
    base_url, token = require_guard()
    send = _via_openai if args.client == "openai" else _via_urllib
    results = []
    for index in range(args.requests):
        spec = dict(REQUESTS[index % len(REQUESTS)])
        name = spec.pop("name")
        started = time.monotonic()
        status, payload = send(base_url, token, {"model": args.model, **spec})
        choice = (payload.get("choices") or [{}])[0] if isinstance(payload, dict) else {}
        message = choice.get("message") or {}
        tool_calls = message.get("tool_calls") or []
        content = message.get("content")
        results.append(
            {
                "index": index,
                "request": name,
                "client": args.client,
                "http_status": status,
                "error_code": (payload.get("error") or {}).get("code") if isinstance(payload, dict) else None,
                "model_echo": payload.get("model") if isinstance(payload, dict) else None,
                "finish_reason": choice.get("finish_reason"),
                "tool_calls": [
                    {"name": (call.get("function") or {}).get("name"),
                     "arguments_json_ok": _json_ok((call.get("function") or {}).get("arguments"))}
                    for call in tool_calls
                ],
                "reply_prefix": content[:80] if isinstance(content, str) else None,
                "usage": payload.get("usage") if isinstance(payload, dict) else None,
                "latency_ms": int((time.monotonic() - started) * 1000),
            }
        )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"schema": "auditor-route-canary/v1", "results": results}, indent=2) + "\n",
                        encoding="utf-8")
    ok = sum(1 for r in results if r["http_status"] == 200)
    print(json.dumps({"requests": len(results), "ok": ok}))
    return 0 if ok == len(results) else 1


def _json_ok(text: object) -> bool:
    if not isinstance(text, str):
        return False
    try:
        json.loads(text)
        return True
    except json.JSONDecodeError:
        return False


if __name__ == "__main__":
    sys.exit(main())
