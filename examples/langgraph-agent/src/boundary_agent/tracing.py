"""Trace normalization utilities."""
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from langchain_core.messages import BaseMessage

TRACE_SCHEMA_VERSION = "1.0"


def serialize_message(message: BaseMessage) -> dict[str, Any]:
    return {
        "message_type": message.type,
        "content": message.content,
        "message_id": message.id,
        "name": message.name,
        "tool_calls": getattr(message, "tool_calls", []),
        "tool_call_id": getattr(message, "tool_call_id", None),
    }


def create_trace_event(
        *,
        run_id: str,
        sequence: int,
        event_type: str,
        data: dict[str, Any],
) -> dict[str, Any]:
    if not run_id:
        raise ValueError("run_id must not be empty")

    if sequence < 1:
        raise ValueError("sequence must be at least 1")

    if not event_type:
        raise ValueError("event_type must not be empty")

    return {
        "schema_version": TRACE_SCHEMA_VERSION,
        "run_id": run_id,
        "sequence": sequence,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "data": data,
    }

def append_trace_event(
        path: str | Path,
        event: dict[str, Any],
) -> None:
    trace_path = Path(path)
    trace_path.parent.mkdir(parents=True, exist_ok=True)

    with trace_path.open("a", encoding="utf-8") as trace_file:
        trace_file.write(json.dumps(event, ensure_ascii=False))
        trace_file.write("\n")

class TraceRecorder:
    def __init__(
            self,
            *,
            run_id: str,
            path: str | Path,
    ) -> None:
        if not run_id:
            raise ValueError("run_id must not be empty")

        self.run_id = run_id
        self.path = Path(path)
        self._next_sequence = 1

    def record(
            self,
            *,
            event_type: str,
            data: dict[str, Any],
    ) -> dict[str, Any]:
        event = create_trace_event(
            run_id=self.run_id,
            sequence=self._next_sequence,
            event_type=event_type,
            data=data,
        )
        append_trace_event(self.path, event)
        self._next_sequence += 1
        return event