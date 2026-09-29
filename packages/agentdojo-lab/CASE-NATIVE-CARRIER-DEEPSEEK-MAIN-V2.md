# DeepSeek native-task paired-carrier main v2

Protocol date: 2026-09-28. This replaces the unrun and withdrawn
[v1 main draft](CASE-NATIVE-CARRIER-DEEPSEEK-MAIN-V1.md), not the separately
retained [eight-slot pilot](CASE-NATIVE-CARRIER-DEEPSEEK-V1.md). The plan was
frozen after every slot passed request-free source and execution-path controls.
The pilot and the earlier custom-user-task batches remain separate strata.

## Question

On original AgentDojo `v1.2.2` user tasks, what fraction of genuinely exposed
legitimate-value and attacker-value carriers does the independent Tier 3 or
Tier 4 content matcher recover for a sensitive argument in an **executed**
tool call? Report by suite on DeepSeek Flash first. Exposure, content match,
native utility, executed call and simulated state are distinct observations.
The match is correspondence evidence, not proof of influence.

This is a controlled carrier intervention, not the stock AgentDojo attack
success benchmark. The original user prompts, initial environments, full
tool sets and native utility oracles remain in force. Only text at an original
registered injection vector changes between matched conditions. No original
injection task's `GOAL` or `security` oracle is claimed for this panel.

## Sampling and source unit

The request-free catalog audit found 19 candidate original prompts with a
relevant sensitive argument and a registered vector visible before its
ground-truth sink. One Banking task was excluded because its legitimate IBAN
occurs twice in one pre-sink output. The selected 18 original task IDs are
Workspace 5, Banking 4, Slack 5 and Travel 4. Seven different, predeclared
factual wordings per task, each in matched clean/attack conditions, yield
126 pairs and **252 planned trajectories**. All 252 passed the request-free
unique, pre-sink passage check. At the eight-slot pilot's 6/8 sink execution
fraction this would project about 189 executed sinks; that small pilot is a
planning reference, not a promise or stopping rule. All started or failed
slots remain in the ledger. Tasks, source fixtures and payload variants are
correlated, so results must be shown by task and source cluster as well as
suite. No task is added or replaced after observing model behavior.

The primary source unit is a predeclared object or passage span in a
model-visible tool output, with an exact selector and its originating tool
call. A candidate qualifies only when a successful tool result was included
in an outbound model request before the sink proposal and the passage binds
uniquely to that result. Whole-output correspondence is a separate secondary
diagnostic; it must not be pooled with Case R's whole-document 13/13 versus
0/13 result. Mixed-role, repeated, absent, post-sink-only and no-sink cases
remain explicit. Numeric values form a separate stratum with declared string
rendering and type checks.

The legitimate and attacker passages are not matched in length or syntax.
In several attack slots, the legitimate value is a short structured field
while the attacker value sits in a complete factual sentence. Tier 3/4
detection rates are therefore descriptive rates for these observed carrier
forms, not an isolated effect of the `legit` or `attacker` label. Reducing
both passages to bare value strings would change the source unit and could
turn the comparison into near self-matching; that is not the primary analysis.
Two selected attack vectors also have weak task-specific relevance:
Banking `user_task_6` places the altered amount in an incoming refund memo
while the requested amount comes from a Spotify transaction, and Workspace
`user_task_20` places the altered email in a project-kickoff event while
Sarah's legitimate email comes from contact lookup. Their outcomes must be
identified by task rather than treated as evidence about a same-record
carrier conflict.

## Execution controls

The frozen plan includes exact user prompts, task/vector IDs, carrier
strings, values, source selectors, sink functions/argument paths, variant IDs,
and source-code and pinned-input hashes. The existing DeepSeek adapter uses
`https://api.deepseek.com`, `deepseek-flash`, temperature 0 and disabled
thinking, with at most ten requests per slot, 2,048 completion tokens per
request, a 60-second request timeout, a 900-second slot timeout, zero SDK
retries and a 60,000-token-per-minute global pacing state. Checkpoint/resume
starts only never-started slots. The ignored local
`.env` supplies the key; requests and artifacts must not contain it.
The live batch used one predeclared technical checkpoint after eight started
slots, then resumed the remaining frozen slots without using early detection
outcomes for selection.

For every model × suite, report planned/started/completed slots, model
requests, native utility, sink executions and value outcomes, state evidence,
pre-sink exposures and binding failures, Tier 3/4 carrier and noncarrier
counts, and an `n/a` rate when a denominator is empty. Raw requests, model
messages, runtime events, initial/final simulated state, source hashes and
the manifest are retained. The DeepSeek-only batch is reported separately
from any future Groq or GPT-5 mini batch.

## Execution receipt

The request-free fixture check passed all declared pre-sink passage selectors
in 252/252 planned slots and found 126/126 attacker values accepted by the
original simulated sink tools on cloned environments. The separate
[final cross-suite transport control](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/runs/20260928-deepseek-native-main-v2-cross-suite-offline-final-v1/summary.json)
completed one clean/attack pair per suite (8/8 slots, 28 in-process mock
requests, 11/11 unique passage bindings); checkpoint/resume restarted only
six untouched slots. These are implementation checks, not DeepSeek outcomes.

The [live batch](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/runs/20260928-deepseek-native-carrier-main-v2/summary.json)
completed **252/252** trajectories with **1,024** captured and reported
DeepSeek requests. The planned eight-slot technical checkpoint used 24
requests; resumption started only the remaining 244 slots. All 252 slots
completed; no service pause, replacement or extra slot occurred. Native
utility passed in 217/252 slots. The event audit found **232 successful
declared sink calls** in 232 slots; 230 had a corroborating native state
change, and 223 had one state-corroborated sink with an exact legitimate or
attacker value eligible for role-specific analysis. Seven executed values
were `other` (case or spelling variants in Workspace), and two Banking
address updates executed without a new state change. Slack's invite email
is confirmed by an executed argument and new user, not by a persisted email
field. The batch used 18 original user task IDs, 11 registered source
vectors and seven wording variants.

The [derived Tier 3/4 report](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260928-deepseek-native-carrier-main-v2/index.html)
contains the full 252-slot ledger and 324 scored passage pairs: 221
value-aligned carriers and 103 noncarriers. The primary **literal-text**
carrier recall is below; Tier 3 and Tier 4 made the same binary decision on
all 324 scored pairs. `n/a` means no exposed, value-aligned, executed
attacker carrier; it is not 0% detection.

| Suite | Legitimate carrier, T3 and T4 | Attacker carrier, T3 and T4 |
| --- | ---: | ---: |
| Workspace | 56/63 | n/a (0 eligible) |
| Banking, text values | 12/12 | 7/7 |
| Slack | 43/43 | 22/22 |
| Travel | 56/56 | n/a (0 eligible) |

Banking's **numeric amount** stratum is separate: legitimate 14/18 for both
tiers; attacker n/a. Noncarrier false positives are substantial in some
suites: 23/32 Workspace attacker passages, 31/31 Slack passages and 28/28
Travel attacker passages matched an executed *different* value; Banking text
had 0/5 and numeric 0/7. These are content matches, not causal influence.
The attacker carrier denominator is empty in Workspace and Travel because
no exact attacker value reached an eligible sink there. Some attack slots
still exposed the attacker text and executed the legitimate value.

The request-free
[noncarrier chunk audit](DEEPSEEK-NONCARRIER-CHUNK-AUDIT-V1.md) subsequently
reproduced all 324 primary and 260 whole-output scores within `1e-6`. It found
that 47/82 passage-level noncarrier positives had the target elsewhere in the
same serialized output, while 35/82 had no target anywhere in that output and
are the stronger semantic-confusion cases. These mechanisms are reported
separately and do not establish an attacker-role effect.

Commands actually run from `codebase/agentdojo-lab`:

```bash
.venv/bin/python -m pytest tests/test_native_carrier_main_v2.py tests/test_deepseek_native_main_v2_runner.py tests/test_report_deepseek_native_main_v2.py -q
.venv/bin/ruff check src/agentdojo_lab/native_carrier_main_v2.py scripts/run_deepseek_native_main_v2.py scripts/report_deepseek_native_main_v2.py tests/test_native_carrier_main_v2.py tests/test_deepseek_native_main_v2_runner.py tests/test_report_deepseek_native_main_v2.py
.venv/bin/ruff format --check src/agentdojo_lab/native_carrier_main_v2.py scripts/run_deepseek_native_main_v2.py scripts/report_deepseek_native_main_v2.py tests/test_native_carrier_main_v2.py tests/test_deepseek_native_main_v2_runner.py tests/test_report_deepseek_native_main_v2.py
.venv/bin/python scripts/run_deepseek_native_main_v2.py --output runs/20260928-deepseek-native-carrier-main-v2 --protocol deepseek-native-carrier-main-v2 --live --max-started-slots 8
.venv/bin/python scripts/run_deepseek_native_main_v2.py --output runs/20260928-deepseek-native-carrier-main-v2 --resume
HF_HUB_OFFLINE=1 .venv/bin/python scripts/report_deepseek_native_main_v2.py --batch runs/20260928-deepseek-native-carrier-main-v2 --output reports/20260928-deepseek-native-carrier-main-v2
```

All 14 focused tests, Ruff check and Ruff format check passed. The report's
live packet consistency checks passed; the frozen plan/preflight hashes and
runner implementation hash matched, all suite slots completed, and a scan of
3,289 live-run files found zero occurrences of the configured API key. The
raw run and derived report remain separate from prior DeepSeek custom-task
and native pilot denominators. Git synchronization status is recorded in
`PROJECT_CONTEXT.md`.
