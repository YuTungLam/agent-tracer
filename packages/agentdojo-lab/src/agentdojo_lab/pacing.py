"""Conservative client-side quota pacing; no payload changes or request retries."""

import json
import math
import time
from pathlib import Path
from uuid import uuid4


class RequestPacer:
    """One sequential batch shares recent token reservations across processes.

    Byte estimates are conservative for these English benchmark prompts, not
    an exact provider tokenizer. Actual reported usage replaces each estimate.
    Oversized requests get a separate window but may still be rejected by the
    provider. Failed calls retain their reservation. No completion is retried.
    """

    window_seconds = 65.0

    def __init__(self, tokens_per_minute: int, state_path: Path | None = None):
        self.budget = tokens_per_minute
        self.path = state_path
        self.entries = []

    def _load(self):
        entries = json.loads(self.path.read_text()) if self.path and self.path.exists() else self.entries
        if not isinstance(entries, list) or any(
            not isinstance(e, dict)
            or type(e.get("tokens")) is not int
            or e["tokens"] < 0
            or type(e.get("at")) not in (int, float)
            or not math.isfinite(e["at"])
            or not isinstance(e.get("id"), str)
            for e in entries
        ):
            raise ValueError("Invalid pacing state")
        now = time.time()
        if any(e["at"] > now + self.window_seconds for e in entries):
            raise ValueError("Pacing state has future timestamps")
        self.entries = [e for e in entries if now - e["at"] < self.window_seconds]

    def _save(self):
        if self.path:
            temp = self.path.with_name(self.path.name + ".tmp")
            temp.write_text(json.dumps(self.entries) + "\n")
            temp.replace(self.path)

    def before_request(self, messages, tools) -> tuple[str, float]:
        # Only timestamps/counts reach the state file, never prompts or keys.
        payload = json.dumps({"messages": messages, "tools": tools}, ensure_ascii=False).encode()
        estimate = min(self.budget, math.ceil(len(payload) / 3) + 1024)
        start = time.monotonic()
        while True:
            self._load()
            if sum(e["tokens"] for e in self.entries) + estimate <= self.budget:
                break
            oldest = min(e["at"] for e in self.entries)
            time.sleep(max(0.01, min(5.0, oldest + self.window_seconds - time.time())))
        ticket = uuid4().hex
        self.entries.append({"id": ticket, "at": time.time(), "tokens": estimate})
        self._save()
        return ticket, time.monotonic() - start

    def after_response(self, ticket: str, reported_tokens: int | None):
        self._load()
        for entry in self.entries:
            if entry["id"] == ticket:
                entry["at"] = time.time()
                if type(reported_tokens) is int and reported_tokens >= 0:
                    entry["tokens"] = reported_tokens
                break
        self._save()
