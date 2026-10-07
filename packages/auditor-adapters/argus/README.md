# ARGUS / AgentLure (Warrant) on DeepSeek

Runs the third-party ARGUS artifact (anonymous repo AgentLure, package `agentlure` 0.2.0, defense `Warrant`)
with the agent and **every** Warrant judge on `deepseek-flash`, behind the shared budget guard in
`../common/deepseek_route.py`.

**Fidelity label: backbone-substituted.** The published targets used gpt-4o-mini. A DeepSeek run is a
declared fidelity check of the artifact's behaviour on another backbone, not an exact reproduction.

The artifact has **no licence**. Nothing from it is copied here: these scripts import it from its own venv
(`<external-auditors>/argus/.venv`, Python 3.11, agentdojo 0.1.35, openai 3.26.0). Artifact notes, fidelity
targets and the zero-call cost estimator are in `<external-auditors>/argus/NOTES.md` and `smoke/`.

## Files

| File | Role |
|---|---|
| `argus_wire.py` | Client shim handed to the artifact. Pins `deepseek-flash`, applies the lab DeepSeek wire mapping (developer to system, text blocks joined, tool `name` dropped), sets `thinking` disabled, tags each request with `X-Auditor-Sample`, counts tokens per sample, logs ids, wire facts and usage (never text), and latches on the first budget refusal so nothing else leaves the process. |
| `argus_adapter.py` | Sample designs, zero-call cost estimate, pipeline factories, runner, summary. |
| `run_argus.py` | CLI: `designs`, `plan`, `agentlure`, `agentdojo`, `summarize`. Model calls run only under the guard. |
| `stages.json` | Stage config for `deepseek_route.py run-stage` (DRY, S1, S2, S3): argv, caps, estimates, targets. |
| `tests/` | 26 offline tests against a fake loopback upstream (no model calls). |

## How a request travels

`run-stage` starts the guard on 127.0.0.1 and runs `run_argus.py` from a scratch cwd with
`OPENAI_BASE_URL = AUDITOR_GUARD_URL = guard` and a guard token as `OPENAI_API_KEY`. The artifact builds its
own `openai.OpenAI()` clients (`MeteredClient` in `agentlure.evaluate.run`); our factories wrap them in
`DeepSeekWireClient` and hand them to `undefended_agent(...)` or `Warrant(...)`. Agent and judges share one
model id, so `--model deepseek-flash` covers both. The guard holds the key, forces the model and thinking
off, sets `max_tokens` 4096 when the agent sends none, counts usage and refuses with HTTP 402 at the cap.

`run_argus.py` refuses to make calls unless `OPENAI_BASE_URL` is loopback and equals `AUDITOR_GUARD_URL`.

## Sample validity

- A sample that met **any budget refusal** is written to `<benchmark>-<row>.invalid.jsonl`
  (`invalid_reason: budget_refusal`) and re-run on resume. A refused judge makes Warrant fail closed, and
  that block would be ours, not the artifact's.
- A sample whose run raised is set aside as `sample_error` (the artifact also excludes these).
- **Judge failures from the provider** are the artifact's own fail-closed behaviour: the record is kept,
  `adapter.judge_failures` is set, and `summarize` reports ASR with and without those samples (the
  "abstain" reading in NOTES.md section 5.2).
- Valid records keep the artifact's JSONL format plus an `adapter` field, so `agentlure show` still reads them.
  `adapter.config_sha` covers the adapter version, the wire policy and the artifact's own configuration
  (corpus and implementation hashes). Resume refuses a folder of another configuration.

## Stages

Estimates come from `run_argus.py plan` over the artifact's zero-call estimator rows
(`smoke/estimate_calls_agentlure.json`, `smoke/estimate_calls_agentdojo_v1.2.1.json`). All are UNVERIFIED
for DeepSeek. "High" multiplies by 2.5 for real agent steps, block-and-retry turns and judge retries
(NOTES.md section 6). USD uses the lab snapshot of 2026-09-30, $0.30 per M input and $1.20 per M output
(`agentdojo-lab/configs/pilot_protocol_v1_draft.json`, `budget.price_snapshots`), not re-checked.

| Stage | Scope | Requests (base) | Tokens base / high | USD base / high | Hard cap |
|---|---|---|---|---|---|
| DRY | 1 AgentLure sample, Warrant row, Ollama behind the guard | 10 (cap) | ~9k notional | 0 | 10 requests |
| S1 | 3 samples (banking attacked, travel attacked, slack clean) x 2 rows | ~500 | 0.56M / 1.40M | 0.18 / 0.46 | $1.00, 2.0M tokens, 1,500 requests |
| S2 | 80 attacked + 40 clean x 2 rows (S1 first) | ~23.4k | 32.0M / 79.9M | 10.34 / 25.85 | $26, 80M tokens, 60k requests |
| S3 (optional) | AgentDojo v1.2.1, 20 attacked + 5 clean per suite x 2 rows | ~15.2k | 18.5M / 46.2M | 6.05 / 15.14 | $16, 48M tokens, 40k requests |
| not planned | full AgentLure, 360 x 2 rows | ~72.6k | 102.9M / 257.3M | 33.19 / 82.98 | |

Per episode (base): Warrant on an attacked AgentLure sample is about 262k tokens, about $0.08 (about 225k judge
input incl. about 70 framing tokens per call, 31k agent input, about 6.7k output); the undefended agent about
32k tokens. On AgentDojo: Warrant about 188k, undefended about 19k. The lab measured 13.8k tokens per native
DeepSeek AgentDojo slot (v1.2.2, lab pipeline; `agentdojo-lab/PILOT-PROTOCOL-V1-DRAFT.md` section 9.1), below
the estimator's 18.1k agent input, so the agent side of S3 is not underestimated. Judge completion of 33 tokens per call is the mean of 8 local qwen2.5 calls
(NOTES.md section 4.3); the DRY run saw 6-83.

### Why 80 attacked samples in S2

- **Unbiased for the full corpus.** AgentLure is 4 suites x 10 tasks x 8 vectors, every cell present. S2 keeps
  every margin balanced: 20 per suite, 10 per vector, each user task twice with two different vectors. The
  unweighted rate therefore estimates the full-320 rate. In each suite four vectors get 3 samples and four
  get 2, alternating across suites. The design is seeded and deterministic (`run_argus.py designs`).
- **Enough for the paired contrast.** Under the published rates (28.8% vs 3.8%), about 20 discordant pairs
  are expected (80 x 0.25). Exact McNemar gives p = 2e-6 at 20:0 and 2e-4 at 19:2.
- **Coarse fidelity only.** At n=80 the Wilson 95% interval is 20.0%-39.5% for 23/80 and 1.3%-10.5% for
  3/80. That flags gross departures, not small ones. The clean set stays at all 40 tasks, so clean utility
  and refusal compare directly with 35/40, 3/40 and 37/40.
- **Cost.** About a third of the full run ($10 base vs $33). Order is round-robin over suites, so a capped
  stop leaves a balanced prefix. Rows run interleaved per sample, so pairs complete together.

## Commands

The runner is standard-library Python; the stage argv uses the artifact venv via `{artifact_python}`. Set
`AUDITOR_ARTIFACTS_ROOT` to the external-auditors folder and `AUDITOR_LAB_ENV` to the lab `.env` (read for
the `DEEPSEEK_API_KEY` line only), or pass `--artifact-root` and `--lab-env`. Paid outputs go to an
experiment folder in the results checkout (`--out-root`, outside this repo; the runner refuses paths inside
it). `--grace-seconds 60` lets the adapter write its receipt after a guard halt.

```
python packages/auditor-adapters/common/deepseek_route.py run-stage --artifact argus --stage DRY \
  --cap-usd 0.05 --cap-tokens 200000 --dry-run-ollama --grace-seconds 60 --out-root <smoke-or-results>
python packages/auditor-adapters/common/deepseek_route.py run-stage --artifact argus --stage S1 \
  --cap-usd 1.00 --cap-tokens 2000000 --grace-seconds 60 --out-root <results-experiment-dir>
python packages/auditor-adapters/common/deepseek_route.py run-stage --artifact argus --stage S2 \
  --cap-usd 26 --cap-tokens 80000000 --grace-seconds 60 --out-root <results-experiment-dir> \
  -- --resume-from <S1 out_dir>/adapter
python packages/auditor-adapters/common/deepseek_route.py run-stage --artifact argus --stage S3 \
  --cap-usd 16 --cap-tokens 48000000 --grace-seconds 60 --out-root <results-experiment-dir>
```

After a halt, run the same stage again with `-- --resume-from <halted out_dir>/adapter`; only missing or
set-aside samples run. Then:

```
<artifact python> packages/auditor-adapters/argus/run_argus.py summarize --benchmark agentlure --out <S2 out_dir>/adapter
<artifact python> packages/auditor-adapters/argus/run_argus.py plan --agentlure-estimates <smoke>/estimate_calls_agentlure.json \
  --agentdojo-estimates <smoke>/estimate_calls_agentdojo_v1.2.1.json
```

Gate between stages: go from S1 to S2 only if S1 shows no `sample_error`, `judge_failures` near 0, the judge
returning valid span ids (the 7B dry-run model did not; NOTES.md section 4.3), and tokens per sample within
the high estimate.

## Declared deviations from the published setup

1. Backbone: `deepseek-flash` for the agent and all judges (published: gpt-4o-mini).
2. Wire: developer to system, text blocks joined, tool `name` dropped, thinking disabled (the lab mapping).
3. Agent `max_tokens`: the guard sets 4096 when the artifact sends none.
4. Agent temperature: kept as the artifact sends it. agentdojo 0.1.35 drops `temperature=0.0`, so the
   provider default applies (DeepSeek's default is UNVERIFIED). `--agent-temperature 0` is a declared
   variant with its own `config_sha`.
5. S2 is a stratified 80/320 attacked subset; S3 is a 20+5 per suite subset of the artifact's 80+15 draw.
6. AgentDojo (S3): `important_instructions` still addresses the model as `gpt-4o-mini-2024-07-18` (artifact
   default). In earlier lab native runs DeepSeek produced attacker sinks only in banking and slack, so the
   undefended ASR in S3 may come almost entirely from those suites.
7. Warrant writes one trace per sample to `<out>/traces/`, as `experiments/effectiveness.py` does.

## Tests

```
PYTHONUTF8=1 <artifact python> -m pytest --rootdir=packages/auditor-adapters/argus packages/auditor-adapters/argus/tests -q -p no:cacheprovider
```

## Dry run (2026-10-08, Ollama qwen2.5:7b-instruct behind the guard, stage DRY)

10 requests forwarded (8 judge, 2 agent), then the request cap. Guard status `halted`, exit 3. The ledger shows
judge requests with `response_format` json_object, `max_tokens` 400/800 and `finish_reason` stop, and agent
requests with 16 tools, `max_tokens` 4096 and `tool_calls`. The 11th request was refused with 402. The shim
latched, the sample was set aside as `budget_refusal`, and the artifact's own token meter (8,796) equalled the
guard ledger. This checks plumbing only; it is not evidence about Warrant.
