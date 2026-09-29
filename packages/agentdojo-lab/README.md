# AgentDojo Lab

This package contains the current AgentDojo-based tracing and evaluation work: offline validation, native and causal replay, report generation, frozen experiment protocols, and HPC runners.

## Setup

Use Python 3.12. The bootstrap script clones the exact AgentDojo commit recorded in upstream.json, builds isolated uv state, installs the locked environment with figure support, and creates a local .env from .env.example.

~~~powershell
python scripts/bootstrap.py --python 3.12
.venv/Scripts/dojo-lab.exe doctor
~~~

On POSIX:

~~~sh
python scripts/bootstrap.py --python 3.12
.venv/bin/dojo-lab doctor
~~~

Do not run a plain frozen uv sync before bootstrap: uv.lock intentionally points to the ignored vendor/agentdojo checkout.

## Validation

~~~powershell
.venv/Scripts/python.exe -m pytest
.venv/Scripts/python.exe -m ruff check src tests scripts
~~~

HPC tests live beside the batch runners and are not included by the default pytest testpaths setting:

~~~powershell
.venv/Scripts/python.exe -m pytest hpc/test_*.py
~~~

## Layout

- src/agentdojo_lab: packaged tracing, validation, replay, and reporting code.
- tests: offline package tests.
- scripts: experiment and analysis entry points.
- hpc: cluster runners and their colocated tests.
- configs: frozen executable experiment definitions.
- docs: design contracts retained for reproducibility.

Generated runs, reports, completed annotations, logs, caches, model files, and downloaded vendor code are ignored. Historical closeout configs may refer to evidence that exists only at the source commit listed in ../../docs/EXPERIMENTAL_DATA.md.

HTML files under src/agentdojo_lab are required runtime templates and must remain tracked.
