from langchain_core.messages import HumanMessage, SystemMessage
from langchain_groq import ChatGroq

from boundary_agent import build_graph
from boundary_agent.tools import mock_web_search

MODEL_NAME = "openai/gpt-oss-20b"


def main() -> None:
    model = ChatGroq(model=MODEL_NAME)
    graph = build_graph(
        model,
        tools=[mock_web_search],
    )

    messages = [
        SystemMessage(
            content=(
                "You are a concise assistant. "
                "Use tools when they are needed."
            )
        )
    ]

    print("Terminal agent started. Type 'exit' or 'quit' to stop.")

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if user_input.lower() in {"exit", "quit"}:
            break

        if not user_input:
            continue

        result = graph.invoke(
            {
                "messages": [
                    *messages,
                    HumanMessage(content=user_input),
                ]
            }
        )

        messages = result["messages"]
        print(f"Assistant: {messages[-1].content}\n")


if __name__ == "__main__":
    main()