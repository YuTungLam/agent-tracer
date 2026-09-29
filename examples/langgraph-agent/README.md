# LangGraph Agent Example

A small LangGraph integration showing how to keep untrusted tool output inside an explicit tracing and policy boundary.

## Setup

~~~powershell
uv sync --group dev
uv run pytest
~~~

Run the offline terminal example:

~~~powershell
uv run python examples/terminal_chat.py
~~~

The Groq example requires GROQ_API_KEY:

~~~powershell
uv run python examples/groq_model.py
~~~

See DEMO_RUNBOOK.md for a guided demonstration. Run its commands from this directory, not from the monorepo root.
