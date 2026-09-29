"""Append-only observation events; recorder failures must not affect agent execution."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from datetime import date, datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel


def _json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="python")
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (set, frozenset)):
        # JSON encodings also give heterogeneous sets a stable, comparable order.
        encoded = sorted(_json_dump(json.loads(_json_dump(item, sort_keys=False))) for item in value)
        return [json.loads(item) for item in encoded]
    raise TypeError("Unsupported event value")


def _json_dump(value: Any, *, sort_keys: bool = True) -> str:
    return json.dumps(value, default=_json_default, ensure_ascii=False, sort_keys=sort_keys, allow_nan=False)


class EventRecorder:
    """Persist a snapshot of each event immediately, with explicit loss accounting.

    Event sequences count attempts, so unsuccessful observations leave visible gaps.
    ``event_count`` counts successfully written and flushed lines. ``complete`` is
    false after any recorder error, even if subsequent events can be recorded.
    Known credentials are redacted from all string values and dictionary keys.
    Callers must omit request headers and other credentials from event payloads.
    """

    def __init__(
        self,
        path: Path,
        run_id: str,
        *,
        redactions: tuple[str, ...] = (),
        on_event: Callable[[dict], None] | None = None,
    ):
        self.run_id = run_id
        self._redactions = tuple(sorted({value for value in redactions if value}, key=lambda s: (-len(s), s)))
        self._lock = threading.RLock()
        self._id_sequence = 0
        self._event_sequence = 0
        self._event_count = 0
        self._errors: list[str] = []
        self._failed_event_sequences: list[int] = []
        self._closed = False
        self._last_good_offset = 0
        self._needs_repair = False
        self._on_event = on_event
        self._subscriber_errors: list[str] = []
        # Exclusivity is checked before the agent starts; never overwrite a run.
        self._file = Path(path).open("x", encoding="utf-8", newline="\n")

    def new_id(self, prefix: str) -> str:
        """Return an identifier unique across all identifier types in this run."""
        with self._lock:
            self._id_sequence += 1
            return f"{prefix}:{self._id_sequence:08d}"

    def _redact(self, value: Any) -> Any:
        if isinstance(value, str):
            for credential in self._redactions:
                value = value.replace(credential, "[REDACTED]")
            return value
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        if isinstance(value, dict):
            return {self._redact(key): self._redact(item) for key, item in value.items()}
        return value

    def _error(self, stage: str, error: Exception, sequence: int | None = None) -> None:
        # Exception messages can contain payloads or API credentials. Keep only
        # a stage, exception type, and our own integer sequence in diagnostics.
        suffix = f" (event_sequence={sequence})" if sequence is not None else ""
        self._errors.append(f"{stage}: {type(error).__name__}{suffix}")

    def _repair(self) -> None:
        """Remove a partially written line before allowing another append."""
        self._file.seek(self._last_good_offset)
        self._file.truncate()
        self._file.flush()
        self._needs_repair = False

    def emit(
        self,
        event_type: str,
        data: dict,
        *,
        task_id: str | None = None,
        episode_id: str | None = None,
        model_request_id: str | None = None,
        tool_call_id: str | None = None,
        call_ref: str | None = None,
        parent_event_ids: list[str] | None = None,
    ) -> str | None:
        with self._lock:
            self._event_sequence += 1
            sequence = self._event_sequence
            event_id = self.new_id("event")
            stage = "emit.serialize"
            try:
                if self._closed:
                    stage = "emit.closed"
                    raise ValueError("Recorder is closed")
                event = {
                    "schema_version": 1,
                    "run_id": self.run_id,
                    "event_id": event_id,
                    "event_sequence": sequence,
                    "monotonic_ns": time.monotonic_ns(),
                    "time_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "event_type": event_type,
                    "task_id": task_id,
                    "episode_id": episode_id,
                    "model_request_id": model_request_id,
                    "tool_call_id": tool_call_id,
                    "call_ref": call_ref,
                    "parent_event_ids": parent_event_ids if parent_event_ids is not None else [],
                    "data": data,
                }
                # Round-tripping first converts native models and containers into
                # detached JSON values before redaction, including escaped text.
                # Coerce JSON-compatible numeric keys before sorting: Python
                # cannot directly sort a mapping with both string and int keys.
                snapshot = json.loads(_json_dump(event, sort_keys=False))
                line = _json_dump(self._redact(snapshot)) + "\n"
                stage = "emit.write"
                if self._needs_repair:
                    self._repair()
                self._needs_repair = True
                written = self._file.write(line)
                if written != len(line):
                    raise OSError("Incomplete event write")
                self._file.flush()
                self._last_good_offset = self._file.tell()
                self._needs_repair = False
                self._event_count += 1
                # The subscriber sees only a detached copy of the successfully
                # persisted, redacted observation. Its failure must not turn a
                # good event into a recording gap or interrupt tool execution.
                if self._on_event is not None:
                    try:
                        self._on_event(json.loads(line))
                    except Exception as error:
                        self._subscriber_errors.append(
                            f"on_event: {type(error).__name__} (event_sequence={sequence})"
                        )
                        self._on_event = None
                return event_id
            except Exception as error:
                self._failed_event_sequences.append(sequence)
                self._error(stage, error, sequence)
                if self._needs_repair:
                    try:
                        self._repair()
                    except Exception as repair_error:
                        self._error("emit.repair", repair_error, sequence)
                return None

    def subscriber_status(self) -> dict:
        with self._lock:
            return {"complete": not self._subscriber_errors, "errors": list(self._subscriber_errors)}

    def status(self) -> dict:
        with self._lock:
            return {
                "event_count": self._event_count,
                "event_attempt_count": self._event_sequence,
                "complete": not self._errors,
                "errors": list(self._errors),
                "failed_event_sequences": list(self._failed_event_sequences),
            }

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._file.close()
            except Exception as error:
                self._error("close", error)
