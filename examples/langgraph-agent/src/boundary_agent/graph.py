"""Minimal LangGraph runtime."""
from collections.abc import Callable
from typing import Any
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import ToolMessage
from langchain_core.tools import BaseTool
from langgraph.graph import END, START, MessagesState, StateGraph
from boundary_agent.tracing import serialize_message
from time import perf_counter
TraceCallback = Callable[[str, dict[str, Any]], None]

def build_graph(
    model: BaseChatModel,
    tools: list[BaseTool] | None = None,
    trace_callback: TraceCallback | None = None,
):
    resolved_tools = tools or []
    tools_by_name = {
        tool.name: tool
        for tool in resolved_tools
    }
    bound_model = (
        model.bind_tools(resolved_tools)
        if resolved_tools
        else model
    )

    def model_node(state: MessagesState):
        response = bound_model.invoke(state["messages"])
        return {"messages": [response]}

    def tool_node(state: MessagesState):
        tool_messages = []
        last_message = state["messages"][-1]

        for tool_call in last_message.tool_calls:
            selected_tool = tools_by_name[tool_call["name"]]

            if trace_callback is not None:
                trace_callback(
                    "tool_call_started",
                    {
                        "tool_name": tool_call["name"],
                        "tool_call_id": tool_call["id"],
                        "arguments": tool_call["args"],
                        "state_before": {
                            "messages": [
                                serialize_message(message)
                                for message in state["messages"]
                            ]
                        },
                    },
                )

            tool_started_at = perf_counter()

            try:
                tool_result = selected_tool.invoke(tool_call["args"])
            except Exception as error:
                if trace_callback is not None:
                    trace_callback(
                        "tool_call_failed",
                        {
                            "tool_name": tool_call["name"],
                            "tool_call_id": tool_call["id"],
                            "arguments": tool_call["args"],
                            "error_type": type(error).__name__,
                            "error_message": str(error),
                            "duration_ms": round(
                                (
                                        perf_counter()
                                        - tool_started_at
                                )
                                * 1000,
                                3,
                                ),
                            "state_at_failure": {
                                "messages": [
                                    serialize_message(message)
                                    for message in state["messages"]
                                ]
                            },
                        },
                    )

                raise

            tool_message = ToolMessage(
                content=str(tool_result),
                name=tool_call["name"],
                tool_call_id=tool_call["id"],
            )
            tool_messages.append(tool_message)

            if trace_callback is not None:
                trace_callback(
                    "tool_call_completed",
                    {
                        "tool_name": tool_call["name"],
                        "tool_call_id": tool_call["id"],
                        "output": str(tool_result),
                        "duration_ms": round(
                            (perf_counter() - tool_started_at) * 1000,
                            3,
                            ),
                        "state_after": {
                            "messages": [
                                serialize_message(message)
                                for message in [
                                    *state["messages"],
                                    *tool_messages,
                                ]
                            ]
                        },
                    },
                )

        return {"messages": tool_messages}

    def route_after_model(state: MessagesState):
        last_message = state["messages"][-1]

        if last_message.tool_calls:
            return "tools"

        return "end"

    builder = StateGraph(MessagesState)
    builder.add_node("model", model_node)
    builder.add_node("tools", tool_node)

    builder.add_edge(START, "model")
    builder.add_conditional_edges(
        "model",
        route_after_model,
        {
            "tools": "tools",
            "end": END,
        },
    )
    builder.add_edge("tools", "model")

    return builder.compile()