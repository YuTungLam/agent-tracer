# Cross-suite carrier detection: DeepSeek Flash phase

Protocol date: 2026-09-28. The executable source of truth is
`src/agentdojo_lab/carrier_scale.py`; the runner is
`scripts/run_deepseek_carrier.py`. This is a new protocol. It does not alter
Case R, its runs, or its offline tier diagnostic.

Status: the eight-slot **live pilot completed** (24 requests). The v1 main
batch was not started: its travel oracle incorrectly treated an omitted
optional `description` argument as different from AgentDojo's default empty
string, although both calendar calls executed and created events. The raw v1
run, original scoring, and source-hash-matched runtime snapshot are retained
under `runs/20260928-deepseek-carrier-pilot-v1/`. The correction and subsequent
main batch use a separate v2 protocol; see `CASE-CARRIER-DEEPSEEK-V2.md`.

## Research question and estimand

Case R's independent Tier 3/4 recomputation matched 13/13 legitimate-address
carrier pairs and 0/13 attacker-address carrier pairs at Tier 4. This phase
tests whether that carrier correspondence pattern persists with another model
and beyond document-summary-email tasks. Tier 3 and Tier 4 are recomputed
**independently and unconditionally** from the text actually included in the
next outbound model request. A match is a source/value correspondence flag,
not proof that the source caused the model's decision.

The reported detection rate is matched carrier pairs / scored carrier pairs,
grouped by model, AgentDojo suite, and the **value actually used at the
executed sink** (legitimate or attacker). The report also gives the number of
confirmed sinks, unexposed sources, unknowns, noncarrier false positives, and
sink-level detection. An attack slot that sends to the legitimate target is
counted under the legitimate outcome. A source read or proposed sink alone
does not enter the detection denominator.

## Frozen DeepSeek design

- Native pinned AgentDojo `v1.2.2` environments and simulated tools in four
  suites: workspace, banking, slack, and travel. The tasks are synthetic
  read-to-write tasks, not native benchmark tasks or an attack-success-rate
  estimate.
- Each slot has two declared sources, a legitimate target in source A, and a
  clean secondary source or attacker target/payload in source B. The user
  prompt and target tool are the same across the clean/attack pair. The exact
  source text, tool arguments, slot order, and native-state oracles are in the
  frozen plan and `carrier_scale.py`.
- `deepseek-carrier-pilot-v1`: one clean and one attack slot per suite, eight
  planned slots. Pilot failures stay recorded. A changed payload or task
  requires a separately named protocol.
- `deepseek-carrier-main-v1`: nine clean and nine attack slots per suite, 72
  planned slots. The three-model extension is designed for roughly 216 planned
  slots across Groq `openai/gpt-oss-120b`, DeepSeek `deepseek-flash`, and OpenAI
  `gpt-5-mini`, targeting roughly 200 *executed* sinks. That count is a target,
  not a guaranteed denominator; the latter two model phases need their own
  named endpoint/settings protocols. Historical Case R sinks are reference
  evidence and will not be pooled into this cross-suite rate.
- DeepSeek endpoint `https://api.deepseek.com`, model ID `deepseek-flash`,
  temperature 0, `max_tokens=2048`, thinking explicitly disabled, maximum six
  SDK requests per slot, SDK retries zero, 60-second request timeout. The
  protocol freezes a shared token pacing budget; the plan records its value.
  DeepSeek's current model name and thinking/tool contract are documented in
  [its quick start](https://api-docs.deepseek.com/quick_start/) and
  [thinking guide](https://api-docs.deepseek.com/guides/thinking_mode/).
- Each slot starts in a fresh process and native environment. The event log
  retains requests, responses (including returned model ID/fingerprint when
  provided), proposed calls, runtime returns, state changes, and outbound
  source exposure. Every started slot is retained; 401/402/403/429 pauses
  dispatch, and resume starts only previously untouched slots under identical
  source hashes.

## Native sink evidence

| Suite | Source tools | Sensitive sink argument | Native state check |
| --- | --- | --- | --- |
| workspace | `get_file_by_id` twice | `send_email /recipients/0` | one matching newly sent email |
| banking | `read_file` twice | `send_money /recipient` | one matching new transaction |
| slack | `get_webpage`, `read_inbox` | `send_direct_message /recipient` | one matching new recipient inbox message |
| travel | `get_hotels_address`, `get_rating_reviews_for_hotels` | `create_calendar_event /location` | one matching new calendar event |

The offline scorer requires a fixture-declared source ID and exact carrier
passage to bind each model-visible source, and uses the pinned
`all-MiniLM-L6-v2` revision from Case R. Nonmatching or missing bindings stay
unknown. It does not replace the canonical ordered cascade: Tier 2 may stop
that cascade before Tier 3/4 execute online.

## Commands

From `codebase/agentdojo-lab` with Python 3.12:

```bash
.venv/bin/python scripts/run_deepseek_carrier.py --output runs/20260928-deepseek-carrier-offline-pilot-v1
.venv/bin/python scripts/run_deepseek_carrier.py --output runs/20260928-deepseek-carrier-pilot-v1 --live
.venv/bin/python scripts/report_carrier_scale.py --batch runs/20260928-deepseek-carrier-pilot-v1 --output reports/20260928-deepseek-carrier-pilot-v1
.venv/bin/python scripts/run_deepseek_carrier.py --output runs/20260928-deepseek-carrier-main-v1 --protocol deepseek-carrier-main-v1 --live
.venv/bin/python scripts/report_carrier_scale.py --batch runs/20260928-deepseek-carrier-main-v1 --output reports/20260928-deepseek-carrier-main-v1
```

The first command is a scripted HTTP transport control with zero network
requests. Live commands load `DEEPSEEK_API_KEY` from the ignored local `.env`;
the key is not included in the plan or artifacts. Use `--resume --output PATH`
only after a recorded service pause. Report generation makes zero API requests.

## Interpretation and continuation

Compare detection **within** each model/suite/outcome cell. Do not treat
carrier correspondence as influence or a simulated sink proposal as an
executed action. Report slot reachability and all failed/unstarted slots with
the conditional detection rate. Keep changes in model, endpoint, payload,
budget, or interpretation under separately named protocols. The Groq and
OpenAI phases should use the same frozen content and native oracles, with
provider-specific transport settings declared before any live request.
