"""Run the minimal graph without an API key or network connection."""

from langchain_core.language_models.fake_chat_models import (
    FakeMessagesListChatModel,
)
from langchain_core.messages import AIMessage

from boundary_agent import build_graph


model = FakeMessagesListChatModel(
    responses=[AIMessage(content="Received: What is an agent?")]
)
graph = build_graph(model)

result = graph.invoke(
    {"messages": [{"role": "user", "content": "What is an agent?"}]}
)

for message in result["messages"]:
    print(f"{message.type}: {message.content}")