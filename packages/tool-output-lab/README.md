# Tool-Output Injection Lab

A sandboxed harness for matched tool-output injection studies. It provides synthetic tasks, clean/placebo/attack construction, trace validation, a memory-propagation testbed, provider adapters, and a simulated sensitive sink.

The default offline path uses synthetic CANARY values and cannot create a real external effect.

## Setup and tests

~~~powershell
python -m pip install -e .
python -m unittest discover -s tests -q
python -m tool_output_lab --help
~~~

Optional live-provider adapters are installed explicitly:

~~~powershell
python -m pip install -e ".[gemini]"
python -m pip install -e ".[groq]"
~~~

Keep provider keys in environment variables or an untracked .env file. A live smoke or calibration run is not a held-out evaluation and must not be reported as an attack-success-rate estimate.

## Main modules

- conditions.py and attack_spec.py define matched treatments and provenance.
- experiment.py and propagation.py coordinate bounded runs.
- tracing.py records the event stream.
- qualification.py and compare.py enforce evidence eligibility and comparisons.
- tools.py contains the in-process source tool and simulated sink.

Generated traces and result directories belong outside the code repository; see ../../docs/EXPERIMENTAL_DATA.md.
