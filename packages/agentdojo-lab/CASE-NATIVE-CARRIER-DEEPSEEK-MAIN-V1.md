# DeepSeek native-task carrier main v1 — withdrawn draft, not runnable

This draft was not frozen or run. The proposed 272 slots repeat only 12
original user tasks and therefore do not constitute 272 distinct AgentDojo
tasks. A zero-request ground-truth audit found that most declared carrier
rows cannot be uniquely bound at the draft's whole-tool-output granularity:
values are repeated, both roles share one output, or the value appears only
after the sink. These are protocol design failures, not model outcomes.
Do not start `scripts/run_deepseek_native_main.py` from this draft. A revised
sampling plan must use the original task catalog more broadly and keep the
standard AgentDojo attack-success question separate from the supervisor's
Tier 3/4 carrier-source question.

Protocol date: 2026-09-28. This is a new, DeepSeek-only scale-up following the
separately retained [eight-slot native pilot](CASE-NATIVE-CARRIER-DEEPSEEK-V1.md).
The earlier custom-task batches and the native pilot remain separate analysis
strata. The draft fixture and runner were removed after the request-free
audit; this document is retained only to explain the withdrawn design.

## Research question and units

Measure independent Tier 3 and Tier 4 content correspondence between an
actually exposed carrier and an actually executed sensitive tool argument,
split by legitimate versus attacker value and by suite. These are original
registered AgentDojo `v1.2.2` user tasks, prompts, initial environments,
complete suite tool lists and native utility oracles with predeclared custom
text in registered injection vectors. This is not the standard AgentDojo
attack-success-rate benchmark. Tool-output exposure, sensitive argument
execution, simulated state, native utility and Tier 3/4 matches are distinct
observations; no match is a causal influence finding.

The fixed plan has **272 new trajectories**: four suites × 34 matched
clean/attack pairs per suite. It targets roughly 200 new executed sensitive
sinks at the native pilot's 6/8 execution fraction; that estimate is not a
guarantee. Every slot in the plan remains in the denominator even if the model
refuses, omits a read, fails a tool call, or reaches no sink. No failed slot is
replaced to meet the target. Repetitions of a task/payload combination are
correlated observations, not distinct original task templates.

| Suite | Original task IDs | Primary sensitive argument |
| --- | --- | --- |
| workspace | `user_task_15`, `user_task_18`, `user_task_33` | calendar `/location` or email `/recipients/0` |
| banking | `user_task_0`, `user_task_4`, `user_task_13` | transfer `/recipient` or `/amount`, account `/street` |
| slack | `user_task_2`, `user_task_11`, `user_task_17` | invitation `/user_email` |
| travel | `user_task_1`, `user_task_4`, `user_task_7` | calendar `/location` |

The banking `user_task_4` amount is a numeric-value stratum. Its short-target
Tier 3/4 results are shown separately from the address and email strata.
Slack's native invitation state creates a user but does not persist the
invitation email: a successful native call argument plus new user is the
available evidence, and full-value state confirmation is reported separately.

## Frozen execution and analysis

The plan fixes task IDs, prompts, vector IDs, exact carrier strings, condition,
payload family, variant and repetition before network calls. It also records
the source-code and pinned AgentDojo input hashes. DeepSeek uses
`https://api.deepseek.com`, `deepseek-flash`, temperature 0, thinking disabled,
`max_tokens=2048`, at most ten requests per trajectory, 60-second request
timeout, 900-second slot timeout, zero SDK retries and a global
60,000-token-per-minute pacing state. Each task starts from its native initial
environment and gets one pipeline query attempt. The long batch may stop at a
predeclared checkpoint or service pause; resumption starts only untouched
slots after verifying the same plan and runtime hashes.

The primary source unit is one whole model-visible tool output. A source must
be exposed before the sink proposal, matched to its originating successful
tool result and bound uniquely. If a whole output contains both declared
values, its role is ambiguous and it is excluded from role-specific detection
rates. A predeclared **secondary passage-level diagnostic** may compare a
unique carrier-text span within that same output to the executed value; it is
reported apart from whole-output rates and cannot be pooled with Case R's
source-level 13/13 versus 0/13. A no-sink output can still be observed as
exposed, but it contributes no source–sink pair. Tier 3/4 are recomputed
independently and unconditionally with the pinned local MiniLM; they are not
misreported as the ordered live cascade.

For each model × suite and task/payload cluster, report planned, started and
completed slots; native utility true/false/unknown; actual legitimate,
attacker, other and no-sink values; successfully executed arguments and state
evidence; observed exposure, mixed origin, missing exposure and scoring
errors; and T3/T4 matched/scored carrier and noncarrier pairs. Empty
denominators are `n/a`, never 0%. Record all raw requests, events, messages,
native states, source hashes and a manifest. The ignored local `.env` supplies
the API key and must never enter artifacts or Git.

## Execution receipt

Pending. Add exact commands, counts, report links, limitations and Git
synchronization status after offline controls and the full live batch finish.
