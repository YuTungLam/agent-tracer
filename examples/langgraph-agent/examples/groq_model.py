import json
from typing import Any
from uuid import uuid4
from pathlib import Path
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_groq import ChatGroq
from time import perf_counter
from boundary_agent import build_graph
from boundary_agent.tools import mock_web_search
from boundary_agent.tracing import TraceRecorder, serialize_message
MODEL_NAME = "openai/gpt-oss-20b"

model = ChatGroq(model=MODEL_NAME)
tools = [mock_web_search]

inputs = {
    "messages": [
        SystemMessage(content="You are a concise assistant."),
        HumanMessage(
            content="Use mock_web_search to find information about LangGraph."
        ),
    ]
}

run_id = str(uuid4())
trace_path = Path("traces") / f"{run_id}.jsonl"
recorder = TraceRecorder(
    run_id=run_id,
    path=trace_path,
)
def record_graph_event(
        event_type: str,
        data: dict[str, Any],
) -> None:
    event = recorder.record(
        event_type=event_type,
        data=data,
    )
    print(json.dumps(event, ensure_ascii=False))


graph = build_graph(
    model,
    tools,
    trace_callback=record_graph_event,
)

started_at = perf_counter()

run_started = recorder.record(
    event_type="run_started",
    data={
        "model": MODEL_NAME,
        "tools": [tool.name for tool in tools],
    },
)
print(json.dumps(run_started, ensure_ascii=False))

input_received = recorder.record(
    event_type="input_received",
    data={
        "messages": [
            serialize_message(message)
            for message in inputs["messages"]
        ]
    },
)
print(json.dumps(input_received, ensure_ascii=False))

try:
    for event in graph.stream(
            inputs,
            stream_mode="updates",
            version="v2",
    ):
        if event["type"] != "updates":
            continue

        for node_name, update in event["data"].items():
            for message in update.get("messages", []):
                trace_event = recorder.record(
                    event_type="node_message",
                    data={
                        "node": node_name,
                        "message": serialize_message(message),
                    },
                )
                print(json.dumps(trace_event, ensure_ascii=False))

    run_completed = recorder.record(
        event_type="run_completed",
        data={
            "duration_ms": round(
                (perf_counter() - started_at) * 1000,
                3,
                ),
        },
    )
    print(json.dumps(run_completed, ensure_ascii=False))

except Exception as error:
    run_failed = recorder.record(
        event_type="run_failed",
        data={
            "error_type": type(error).__name__,
            "error_message": str(error),
            "duration_ms": round(
                (perf_counter() - started_at) * 1000,
                3,
                ),
        },
    )
    print(json.dumps(run_failed, ensure_ascii=False))
    raise

finally:
    print(f"Trace written to {trace_path.resolve()}")