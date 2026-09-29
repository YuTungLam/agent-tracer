# Agent Tracer

Agent Tracer is a compact research monorepo for studying tool-output injection, propagation, provenance, and agent behavior. It consolidates the useful code from the former feature branches without carrying their generated runs, rendered reports, caches, or branch history.

This is research software. Tool output and saved traces may contain adversarial text; treat them as data, not as instructions.

## Repository layout

| Path | Purpose | Python |
| --- | --- | --- |
| packages/agentdojo-lab | AgentDojo experiments, tracing, causal replay, reporting, and HPC protocols | 3.12 |
| packages/tool-output-lab | Synthetic matched-condition harness and propagation testbed | 3.11+ |
| examples/langgraph-agent | Small LangGraph integration and terminal demo | 3.11+ |
| docs | Migration provenance and experimental-data policy | n/a |

The three projects retain their existing import names and dependency files. This avoids a risky namespace rewrite while a shared agent_tracer API is designed.

## Quick start

Clone the repository and choose the component you need.

For the dependency-pinned AgentDojo lab:

~~~powershell
Set-Location packages/agentdojo-lab
python scripts/bootstrap.py --python 3.12
.venv/Scripts/dojo-lab.exe doctor
~~~

On POSIX systems, the final command is .venv/bin/dojo-lab doctor.

For the offline synthetic harness:

~~~powershell
Set-Location packages/tool-output-lab
python -m pip install -e .
python -m unittest discover -s tests -q
python -m tool_output_lab --help
~~~

For the LangGraph example:

~~~powershell
Set-Location examples/langgraph-agent
uv sync --group dev
uv run pytest
uv run python examples/terminal_chat.py
~~~

Each component README contains more detail.

## Evidence policy

Generated runs and reports are intentionally absent and ignored. The original public repository remains the immediate immutable historical archive at commit [f761e088](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/tree/f761e0883452a1c52234d92978ca4511ac4bea51). See [experimental data](docs/EXPERIMENTAL_DATA.md) before copying any evidence: raw artifacts can contain complete prompts, tool arguments, URLs, model output, and blinded-review mappings.

Only source templates remain. In particular, HTML files under packages/agentdojo-lab/src/agentdojo_lab are runtime assets, not generated reports.

## Provenance and branch policy

The exact source commits, retained content, and exclusions are recorded in [MIGRATION.md](docs/MIGRATION.md). This repository starts with fresh history and uses main as its only long-lived branch. The source repository and all of its branches were left unchanged.

No project-wide license was present in the source repository, so this migration does not invent one. Add an explicit license before relying on public reuse rights.
