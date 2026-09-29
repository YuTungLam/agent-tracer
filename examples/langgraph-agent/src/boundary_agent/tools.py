"""Local tools available to the agent."""

from langchain_core.tools import tool


_SEARCH_INDEX = {
    "langgraph": (
        "LangGraph is a framework for building stateful agent workflows."
    ),
    "tool-output injection": (
        "Tool-output injection occurs when untrusted tool content "
        "influences agent control flow."
    ),
}


@tool
def mock_web_search(query: str) -> str:
    """Search a deterministic local index."""
    normalized_query = query.strip().lower()
    return _SEARCH_INDEX.get(normalized_query, "No results found.")