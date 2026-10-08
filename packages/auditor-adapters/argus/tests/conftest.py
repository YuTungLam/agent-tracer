"""Fixtures: a fake OpenAI-compatible upstream on loopback. No real model is ever called."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ADAPTER_DIR = Path(__file__).resolve().parents[1]
if str(ADAPTER_DIR) not in sys.path:
    sys.path.insert(0, str(ADAPTER_DIR))

JUDGE_REPLY = {
    "invariants": [{"id": "I1", "kind": "type", "text": "t"}, {"id": "I2", "kind": "scope", "text": "s"},
                   {"id": "I3", "kind": "authorization", "text": "a"}],
    "failed": [],
    "support": ["q"],
}


class FakeUpstream:
    """Records every request; answers agent requests with a final answer and judge requests with JSON."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.lock = threading.Lock()
        self.refuse_after: int | None = None  # HTTP 402 "budget" refusals from this request count on
        self.fail_status: int | None = None  # a non-budget error status for every request
        # Optional scripted replies: responder(body) -> assistant message dict (or None for the default).
        self.responder = None
        server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        server.daemon_threads = True
        self.server = server
        self.url = f"http://127.0.0.1:{server.server_address[1]}/v1"
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.thread.start()

    def _handler(self):
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # keep test output quiet
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with upstream.lock:
                    upstream.requests.append({"path": self.path, "body": body,
                                              "headers": {k.lower(): v for k, v in self.headers.items()}})
                    n = len(upstream.requests)
                if upstream.fail_status is not None:
                    return self._send(upstream.fail_status, {"error": {"message": "upstream exploded"}})
                if upstream.refuse_after is not None and n > upstream.refuse_after:
                    return self._send(402, {"error": {"message": "stage budget exhausted", "code": "budget"}})
                scripted = upstream.responder(body) if upstream.responder is not None else None
                if body.get("tools"):
                    message = scripted or {"role": "assistant", "content": "Done."}
                    usage = {"prompt_tokens": 100, "completion_tokens": 5, "total_tokens": 105}
                else:
                    message = scripted or {"role": "assistant", "content": json.dumps(JUDGE_REPLY)}
                    usage = {"prompt_tokens": 50, "completion_tokens": 10, "total_tokens": 60}
                finish = "tool_calls" if message.get("tool_calls") else "stop"
                return self._send(200, {"id": f"fake-{n}", "object": "chat.completion", "created": 0,
                                        "model": body.get("model"),
                                        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                                        "usage": usage})

            def _send(self, status, payload):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        return Handler

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def upstream(monkeypatch):
    fake = FakeUpstream()
    monkeypatch.setenv("OPENAI_BASE_URL", fake.url)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-key")
    yield fake
    fake.close()
