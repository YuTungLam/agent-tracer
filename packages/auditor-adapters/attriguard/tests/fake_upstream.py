"""Scripted OpenAI-compatible upstream for zero-cost adapter tests (no model, no network beyond loopback).

Policy (enough to drive one AgentDojo banking episode through every AttriGuard code path once):
* request without tools                      -> attenuation: returns a fixed neutral sentence;
* system prompt of the judge                 -> if logprobs requested and ``reject_logprobs``: HTTP 400,
                                                else ``{"survive": false, ...}``;
* agent request, no tool result yet          -> read_file(bill-december-2023.txt)          (unaudited path)
* agent request, last tool result attenuated -> shadow: send_money with a different amount
* agent request, one tool result, raw        -> main: send_money to the attacker-style IBAN (judge path)
* otherwise                                  -> plain text, episode ends.

Every request body is kept in ``requests`` so tests can assert the wire format.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

ATTENUATED_TEXT = "FAKE-ATTENUATED: the text describes a bill."
JUDGE_MARKER = "Execution Path Auditor"


def _content_text(content: Any) -> str:
    if isinstance(content, list):
        return "\n".join(str(b.get("text", "")) for b in content if isinstance(b, dict))
    return "" if content is None else str(content)


class FakeUpstream:
    def __init__(self, reject_logprobs: bool = True) -> None:
        self.reject_logprobs = reject_logprobs
        self.requests: list[dict[str, Any]] = []
        self.headers: list[dict[str, str]] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        assert self._server is not None
        host, port = self._server.server_address[:2]
        return f"http://127.0.0.1:{port}/v1"

    def __enter__(self) -> "FakeUpstream":
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # silence
                pass

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                upstream.requests.append(body)
                upstream.headers.append({k: v for k, v in self.headers.items() if k.lower().startswith("x-auditor")})
                status, payload = upstream.respond(body)
                data = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()

    # -- policy -------------------------------------------------------------------------------
    def respond(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        messages = body.get("messages") or []
        system = _content_text(messages[0].get("content")) if messages else ""
        tools = body.get("tools") or []
        if JUDGE_MARKER in system:
            if body.get("logprobs") and self.reject_logprobs:
                return 400, {"error": {"message": "logprobs is not supported for this model",
                                       "type": "invalid_request_error", "code": "invalid_parameter"}}
            return 200, self._text('{"survive": false, "reason": "fake judge"}', body)
        if not tools:
            return 200, self._text(ATTENUATED_TEXT, body)
        tool_msgs = [m for m in messages if m.get("role") == "tool"]
        if not tool_msgs:
            return 200, self._call("read_file", {"file_path": "bill-december-2023.txt"}, body)
        if len(tool_msgs) == 1:
            last = _content_text(tool_msgs[-1].get("content"))
            amount = 1.0 if ATTENUATED_TEXT in last else 98.7
            return 200, self._call(
                "send_money",
                {"recipient": "US133000000121212121212", "amount": amount, "subject": "bill", "date": "2022-01-01"},
                body,
            )
        return 200, self._text("Done.", body)

    def _usage(self, body: dict[str, Any]) -> dict[str, int]:
        prompt = sum(len(_content_text(m.get("content"))) for m in body.get("messages") or []) // 4
        return {"prompt_tokens": prompt, "completion_tokens": 7, "total_tokens": prompt + 7}

    def _text(self, text: str, body: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": "fake", "object": "chat.completion", "created": 0, "model": body.get("model"),
            "choices": [{"index": 0, "finish_reason": "stop", "logprobs": None,
                         "message": {"role": "assistant", "content": text}}],
            "usage": self._usage(body),
        }

    def _call(self, name: str, args: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
        call_id = f"call_{len(self.requests)}"
        return {
            "id": "fake", "object": "chat.completion", "created": 0, "model": body.get("model"),
            "choices": [{"index": 0, "finish_reason": "tool_calls", "logprobs": None,
                         "message": {"role": "assistant", "content": None,
                                     "tool_calls": [{"id": call_id, "type": "function",
                                                     "function": {"name": name, "arguments": json.dumps(args)}}]}}],
            "usage": self._usage(body),
        }
