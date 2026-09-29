# Local Setup and Demo Runbook

This runbook sets up and runs the LangGraph agent on a Windows machine using PowerShell.

Run all commands from the **examples/langgraph-agent** directory. That directory contains this example's **pyproject.toml**, **src/**, **examples/**, and **tests/** trees.

## Requirements

- Windows PowerShell or PowerShell 7
- Git
- Internet access
- A Groq API key

Official references:

- [uv installation](https://docs.astral.sh/uv/getting-started/installation/)
- [Groq API documentation](https://console.groq.com/docs/quickstart)
- [Groq API keys](https://console.groq.com/keys)

## Clone the repository

Open PowerShell and run:

~~~powershell
git clone https://github.com/YuTungLam/agent-tracer.git
Set-Location .\agent-tracer\examples\langgraph-agent
~~~

If the repository is already present:

~~~powershell
Set-Location .\agent-tracer\examples\langgraph-agent
git fetch origin
git pull --ff-only origin main
~~~

Confirm the active branch:

~~~powershell
git branch --show-current
~~~

Expected output:

~~~text
main
~~~

## Install uv

Install uv with the official Windows installer:

~~~powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
~~~

Close and reopen PowerShell after installation, then verify it:

~~~powershell
uv --version
~~~

Alternatively, install uv with WinGet:

~~~powershell
winget install --id=astral-sh.uv -e
~~~

## Create the environment

From the repository root, synchronize the environment from **uv.lock**:

~~~powershell
uv sync --frozen
~~~

This creates the local **.venv**, selects a compatible Python version, and installs the project and development dependencies.

Verify Python:

~~~powershell
uv run python --version
~~~

The project requires Python 3.11 or newer.

## Configure the Groq API key

Set the key for the current PowerShell session without writing it into the repository:

~~~powershell
$GroqSecret = Read-Host "Enter GROQ_API_KEY" -AsSecureString
$env:GROQ_API_KEY = [System.Net.NetworkCredential]::new("", $GroqSecret).Password
Remove-Variable GroqSecret
~~~

Verify that the variable exists without printing the key:

~~~powershell
if ([string]::IsNullOrWhiteSpace($env:GROQ_API_KEY)) {
    throw "GROQ_API_KEY is not set"
}

Write-Output "GROQ_API_KEY is set for this PowerShell session."
~~~

The variable lasts only for the current PowerShell session. Set it again after opening a new terminal.

Never paste an API key into Python source code, commit it to Git, or display it during a presentation.

## Run the tests

~~~powershell
uv run pytest
~~~

Expected result:

~~~text
12 passed
~~~

The tests cover:

- Direct model responses
- Model-requested tool execution
- Tool result insertion into LangGraph state
- Tool state before and after execution
- Successful and failed tool trace events
- JSONL trace creation and event sequencing

## Run the terminal chat

~~~powershell
uv run python examples/terminal_chat.py
~~~

Suggested prompts:

~~~text
Explain the difference between an agent and a chatbot.
~~~

~~~text
Use mock_web_search to find information about LangGraph.
~~~

~~~text
What did I ask you previously?
~~~

Enter either command to stop:

~~~text
exit
quit
~~~

The terminal chat keeps message history only while the process is running. It does not persist memory after the terminal program exits.

The model may answer directly or request a tool:

~~~text
User input
    |
    v
Model
    |-- no tool call --> final response
    |
    |-- tool call --> tool execution --> ToolMessage --> model --> final response
~~~

## Run the traced agent

~~~powershell
uv run python examples/groq_model.py
~~~

The command prints trace events and creates a JSONL file under:

~~~text
traces/<run_id>.jsonl
~~~

The expected successful event sequence is:

~~~text
1  run_started
2  input_received
3  node_message
4  tool_call_started
5  tool_call_completed
6  node_message
7  node_message
8  run_completed
~~~

Every event includes:

- **schema_version**: trace schema version
- **run_id**: identifier shared by all events in one run
- **sequence**: chronological event number
- **timestamp_utc**: UTC event timestamp
- **event_type**: event category
- **data**: event-specific payload

Tool-boundary events include:

- Tool name
- Tool call ID
- Tool arguments
- Observable message state before execution
- Raw tool output
- Observable message state after execution
- Tool duration
- Error type and message when execution fails

The trace captures observable LangGraph messages and tool state. It does not capture or claim to capture hidden model chain-of-thought.

## Display the latest trace

Select the most recent JSONL file:

~~~powershell
$LatestTrace = Get-ChildItem .\traces\*.jsonl |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

Write-Output $LatestTrace.FullName
~~~

Display a compact event timeline:

~~~powershell
Get-Content -LiteralPath $LatestTrace.FullName |
    ForEach-Object { $_ | ConvertFrom-Json } |
    Select-Object sequence, event_type,
        @{Name="node"; Expression={$_.data.node}},
        @{Name="tool"; Expression={$_.data.tool_name}},
        @{Name="duration_ms"; Expression={$_.data.duration_ms}} |
    Format-Table
~~~

Display readable tool-boundary events:

~~~powershell
Get-Content -LiteralPath $LatestTrace.FullName |
    ForEach-Object { $_ | ConvertFrom-Json } |
    Where-Object {
        $_.event_type -in @(
            "tool_call_started",
            "tool_call_completed",
            "tool_call_failed"
        )
    } |
    ConvertTo-Json -Depth 12
~~~

## Mock search behaviour

**mock_web_search** is a deterministic local tool. It does not access the live internet.

The current local index supports:

~~~text
LangGraph
tool-output injection
~~~

Other search terms may return:

~~~text
No results found.
~~~

This deterministic tool provides a reproducible benign baseline before parameterised malicious tool outputs are introduced.

## Troubleshooting

### uv is not recognized

Close and reopen PowerShell after installing uv, then run:

~~~powershell
uv --version
~~~

### ModuleNotFoundError

Confirm that PowerShell is in the repository root, then synchronize the environment:

~~~powershell
Get-Location
uv sync --frozen
~~~

Always run Python through uv:

~~~powershell
uv run python examples/terminal_chat.py
~~~

### Missing Groq API key

Set **GROQ_API_KEY** again in the current PowerShell session:

~~~powershell
$GroqSecret = Read-Host "Enter GROQ_API_KEY" -AsSecureString
$env:GROQ_API_KEY = [System.Net.NetworkCredential]::new("", $GroqSecret).Password
Remove-Variable GroqSecret
~~~

### uv hardlink warning

If the uv cache and repository are on different drives, uv may fall back to copying files. This affects installation performance, not correctness.

To request copy mode for the current PowerShell session:

~~~powershell
$env:UV_LINK_MODE = "copy"
uv sync --frozen
~~~

### Groq request fails

Check:

- Internet access
- Whether **GROQ_API_KEY** is set
- Whether the Groq account has available quota
- Whether the configured model is available

The configured model is defined by **MODEL_NAME** in the example file.

## Pre-demo checklist

Run:

~~~powershell
git pull --ff-only origin main
uv sync --frozen
uv run pytest
uv run python examples/groq_model.py
~~~

Confirm that:

- All tests pass
- The Groq request succeeds
- Eight successful events are printed
- A new JSONL file appears in **traces/**
- The final event is **run_completed**

Keep one successful trace file available as a fallback in case the live model or network is unavailable during the presentation.
