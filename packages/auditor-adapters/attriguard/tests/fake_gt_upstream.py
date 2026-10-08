"""Loopback OpenAI-compatible upstream that replays AgentDojo ground-truth calls (no model, no network
beyond 127.0.0.1), for the case-runner end-to-end tests.

The episode comes from the ``X-Auditor-Episode`` header the adapter's RoutedClient adds
(``row|selection|case_id|arm|rN``); ``scripts[case_id|arm]`` holds the precomputed calls
(``make_gt_scripts.py``). Policy:

* judge (system prompt holds "Execution Path Auditor"): a request with logprobs gets HTTP 400 (exercises
  the D4 fallback); otherwise ``{"survive": judge_allow}``;
* a request without tools is an attenuation call: a fixed marker sentence;
* an agent request with tools: ``k`` = number of tool messages that are not AttriGuard blocks. The shadow
  (its history holds the attenuation marker) proposes legitimate call ``k`` (or the X call when
  ``shadow_x``); the main agent proposes X call ``k`` for an X-carrying arm, the legitimate call
  otherwise; after the script it answers with the task's GROUND_TRUTH_OUTPUT. A blocked call is
  therefore proposed again in the next step (the AG-H2 path);
* ``halt_after``: every request after that many gets HTTP 402, as the budget guard does on a halt;
* ``stringify_lists``: the main agent sends list arguments as Python-literal strings ("['a@b']").
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

ATTENUATED_TEXT = "FAKE-ATTENUATED observation."
JUDGE_MARKER = "Execution Path Auditor"
BLOCK_MARKER = "[AttriGuardBlocked]"


def _text(content: Any) -> str:
    if isinstance(content, list):
        return "\n".join(str(b.get("text", "")) for b in content if isinstance(b, dict))
    return "" if content is None else str(content)


class GTUpstream:
    def __init__(self, scripts: dict[str, Any], *, judge_allow: bool = True, shadow_x: bool = False,
                 halt_after: int | None = None, stringify_lists: bool = False) -> None:
        self.scripts = scripts
        self.judge_allow = judge_allow
        self.shadow_x = shadow_x
        self.halt_after = halt_after
        self.stringify_lists = stringify_lists
        self.requests: list[dict[str, Any]] = []
        self.headers: list[dict[str, str]] = []
        self.statuses: list[int] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None

    @property
    def base_url(self) -> str:
        assert self._server is not None
        return f"http://127.0.0.1:{self._server.server_address[1]}/v1"

    def __enter__(self) -> "GTUpstream":
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_POST(self) -> None:  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8"))
                headers = {k: v for k, v in self.headers.items() if k.lower().startswith("x-auditor")}
                with upstream._lock:
                    upstream.requests.append(body)
                    upstream.headers.append(headers)
                    n = len(upstream.requests)
                status, payload = upstream.respond(body, headers, n)
                with upstream._lock:
                    upstream.statuses.append(status)
                data = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()

    def respond(self, body: dict[str, Any], headers: dict[str, str], n: int) -> tuple[int, dict[str, Any]]:
        if self.halt_after is not None and n > self.halt_after:
            return 402, {"error": {"message": "stage budget guard halted", "type": "guard_halted"}}
        msgs = body.get("messages") or []
        system = _text(msgs[0].get("content")) if msgs else ""
        if JUDGE_MARKER in system:
            if body.get("logprobs"):
                return 400, {"error": {"message": "logprobs is not supported for this model",
                                       "type": "invalid_request_error"}}
            verdict = "true" if self.judge_allow else "false"
            return 200, self._message(body, content='{"survive": %s, "reason": "fake judge"}' % verdict)
        if not body.get("tools"):
            return 200, self._message(body, content=ATTENUATED_TEXT)
        episode = {k.lower(): v for k, v in headers.items()}.get("x-auditor-episode", "")
        parts = episode.split("|")
        script = self.scripts[f"{parts[2]}|{parts[3]}"]
        tool_msgs = [m for m in msgs if m.get("role") == "tool"]
        shadow = any(ATTENUATED_TEXT in _text(m.get("content")) for m in tool_msgs)
        k = sum(1 for m in tool_msgs if not _text(m.get("content")).startswith(BLOCK_MARKER))
        calls = script["x"] if (not shadow or self.shadow_x) else script["legit"]
        if k < len(calls):
            call = calls[k]
            if self.stringify_lists and not shadow:
                call = {"function": call["function"],
                        "args": {a: (str(v) if isinstance(v, list) else v) for a, v in call["args"].items()}}
            return 200, self._message(body, call=(f"call_{n}", call["function"], call["args"]))
        return 200, self._message(body, content=script["final"])

    @staticmethod
    def _message(body: dict[str, Any], content: str | None = None, call: tuple[str, str, Any] | None = None) -> dict[str, Any]:
        message: dict[str, Any] = {"role": "assistant", "content": content}
        if call:
            message["tool_calls"] = [{"id": call[0], "type": "function",
                                      "function": {"name": call[1], "arguments": json.dumps(call[2])}}]
        prompt = sum(len(_text(m.get("content"))) for m in body.get("messages") or []) // 4
        return {"id": "fake", "object": "chat.completion", "created": 0, "model": body.get("model"),
                "choices": [{"index": 0, "finish_reason": "tool_calls" if call else "stop", "logprobs": None,
                             "message": message}],
                "usage": {"prompt_tokens": prompt, "completion_tokens": 9, "total_tokens": prompt + 9}}
