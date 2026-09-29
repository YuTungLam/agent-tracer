from boundary_agent.tools import mock_web_search


print(mock_web_search.name)
print(mock_web_search.description)
print(mock_web_search.args)

result = mock_web_search.invoke({"query": "LangGraph"})
print(result)