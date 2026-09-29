from boundary_agent.tools import mock_web_search


def test_mock_web_search_returns_known_result() -> None:
    result = mock_web_search.invoke({"query": " LangGraph "})

    assert result == (
        "LangGraph is a framework for building stateful agent workflows."
    )


def test_mock_web_search_returns_fallback() -> None:
    result = mock_web_search.invoke({"query": "unknown"})

    assert result == "No results found."