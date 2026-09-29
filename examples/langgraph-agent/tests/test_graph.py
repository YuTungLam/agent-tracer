import pytest
from typing import Any
from langchain_core.language_models.fake_chat_models import (
    FakeMessagesListChatModel,
)
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from boundary_agent import build_graph
from boundary_agent.tools import mock_web_search

class ToolCallingFakeModel(FakeMessagesListChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


@tool
def failing_tool(query: str) -> str:
    """Raise a controlled failure for graph tests."""
    raise RuntimeError("Controlled tool failure")


def test_graph_appends_model_response() -> None:
    model = FakeMessagesListChatModel(
        responses=[AIMessage(content="Test response")]
    )
    graph = build_graph(model)

    result = graph.invoke(
        {"messages": [{"role": "user", "content": "hello"}]}
    )

    assert len(result["messages"]) == 2
    assert result["messages"][0].type == "human"
    assert result["messages"][0].content == "hello"
    assert result["messages"][1].type == "ai"
    assert result["messages"][1].content == "Test response"

def test_graph_executes_tool_and_returns_to_model() -> None:
    model = ToolCallingFakeModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "mock_web_search",
                        "args": {"query": "LangGraph"},
                        "id": "call-1",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(
                content="LangGraph is a stateful agent framework."
            ),
        ]
    )
    graph = build_graph(
        model,
        tools=[mock_web_search],
    )

    result = graph.invoke(
        {"messages": [{"role": "user", "content": "Search for LangGraph"}]}
    )

    messages = result["messages"]
    tool_message = messages[-2]
    final_message = messages[-1]

    assert [message.type for message in messages] == [
        "human",
        "ai",
        "tool",
        "ai",
    ]
    assert tool_message.name == "mock_web_search"
    assert tool_message.tool_call_id == "call-1"
    assert tool_message.content == (
        "LangGraph is a framework for building stateful agent workflows."
    )
    assert final_message.content == (
        "LangGraph is a stateful agent framework."
    )

def test_graph_records_tool_state_around_execution() -> None:
    captured_events: list[tuple[str, dict[str, Any]]] = []

    def capture_trace_event(
            event_type: str,
            data: dict[str, Any],
    ) -> None:
        captured_events.append((event_type, data))

    model = ToolCallingFakeModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "mock_web_search",
                        "args": {"query": "LangGraph"},
                        "id": "call-1",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(content="Final answer"),
        ]
    )

    graph = build_graph(
        model,
        tools=[mock_web_search],
        trace_callback=capture_trace_event,
    )

    graph.invoke(
        {"messages": [{"role": "user", "content": "Search for LangGraph"}]}
    )

    assert [
               event_type
               for event_type, _ in captured_events
           ] == [
               "tool_call_started",
               "tool_call_completed",
           ]

    started_data = captured_events[0][1]

    assert started_data["tool_name"] == "mock_web_search"
    assert started_data["tool_call_id"] == "call-1"
    assert started_data["arguments"] == {"query": "LangGraph"}

    state_before = started_data["state_before"]["messages"]

    assert [
               message["message_type"]
               for message in state_before
           ] == ["human", "ai"]
    assert state_before[-1]["tool_calls"][0]["id"] == "call-1"

    completed_data = captured_events[1][1]

    assert completed_data["tool_name"] == "mock_web_search"
    assert completed_data["tool_call_id"] == "call-1"
    assert completed_data["output"] == (
        "LangGraph is a framework for building stateful agent workflows."
    )
    assert completed_data["duration_ms"] >= 0

    state_after = completed_data["state_after"]["messages"]

    assert [
               message["message_type"]
               for message in state_after
           ] == ["human", "ai", "tool"]
    assert state_after[-1]["tool_call_id"] == "call-1"

def test_graph_records_failed_tool_call() -> None:
    captured_events: list[tuple[str, dict[str, Any]]] = []

    def capture_trace_event(
            event_type: str,
            data: dict[str, Any],
    ) -> None:
        captured_events.append((event_type, data))

    model = ToolCallingFakeModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "failing_tool",
                        "args": {"query": "LangGraph"},
                        "id": "call-failed",
                        "type": "tool_call",
                    }
                ],
            )
        ]
    )

    graph = build_graph(
        model,
        tools=[failing_tool],
        trace_callback=capture_trace_event,
    )

    with pytest.raises(
            RuntimeError,
            match="Controlled tool failure",
    ):
        graph.invoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": "Run the failing tool",
                    }
                ]
            }
        )

    assert [
               event_type
               for event_type, _ in captured_events
           ] == [
               "tool_call_started",
               "tool_call_failed",
           ]

    failed_data = captured_events[1][1]

    assert failed_data["tool_name"] == "failing_tool"
    assert failed_data["tool_call_id"] == "call-failed"
    assert failed_data["arguments"] == {"query": "LangGraph"}
    assert failed_data["error_type"] == "RuntimeError"
    assert failed_data["error_message"] == "Controlled tool failure"
    assert failed_data["duration_ms"] >= 0

    state_at_failure = failed_data["state_at_failure"]["messages"]

    assert [
               message["message_type"]
               for message in state_at_failure
           ] == ["human", "ai"]
