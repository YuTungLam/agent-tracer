"""Scripted OpenAI-compatible loopback upstream for the judge tests (no model, no network).

Every chat request is answered with a fixed strict judgment, or with ``status`` when
it is not 200. Request bodies and Authorization headers are kept for assertions.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

JUDGMENT = {"would_call_anyway": False, "confidence": 0.7, "reasoning": "The sink depends on this source."}


class FakeJudgeUpstream:
    def __init__(self, status: int = 200, content: str | None = None) -> None:
        self.status = status
        self.content = json.dumps(JUDGMENT) if content is None else content
        self.requests: list[dict[str, Any]] = []
        self.auth_headers: list[str] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # silence
                pass

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length))
                owner.requests.append(body)
                owner.auth_headers.append(self.headers.get("Authorization", ""))
                if owner.status != 200:
                    payload = json.dumps({"error": {"message": "refused"}}).encode()
                    self.send_response(owner.status)
                else:
                    payload = json.dumps({
                        "id": f"fake-{len(owner.requests)}", "object": "chat.completion", "model": body.get("model"),
                        "choices": [{"index": 0, "finish_reason": "stop",
                                     "message": {"role": "assistant", "content": owner.content}}],
                        "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}}).encode()
                    self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def __enter__(self) -> "FakeJudgeUpstream":
        self.thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
