# Shared DeepSeek route and budget guard

`deepseek_route.py` lets every third-party auditor adapter run with DeepSeek (`deepseek-flash`) as its only paid backbone, under a hard per-stage budget. It uses only the standard library (Python 3.10 or later), so it runs inside each artifact's own venv.

DeepSeek is also the common backbone for the cross-auditor comparison (pilot protocol OPEN-3). The published fidelity targets used other backbones, so every DeepSeek run is labelled **backbone-substituted**. It is a fidelity check, not an exact reproduction.

## Providers: DeepSeek and OpenAI

The guard is provider-aware (the file name stays `deepseek_route.py` because every adapter imports it). A stage declares exactly one provider:

- **DeepSeek** stages live under `stages` in each `stages.json`. Everything in the rest of this README describes them, and their behaviour is unchanged from fe2e3e0 (checked by a differential test, `../RUN-PLAN-OPENAI.md` section 2.6).
- **OpenAI** stages live under a separate top-level `provider_stages` section with `"provider": "openai"` and an exact `models` allowlist priced in `providers.json`. The guard never rewrites the model, adds no `thinking` field, clamps `max_tokens`/`max_completion_tokens` without renaming them, passes logprobs through, forwards `/v1/embeddings`, refuses non-text content parts and billing-changing fields, and charges every request against the stage caps. Runners older than this change read only `stages`, so they can never run an OpenAI stage as a DeepSeek one.
- `blocked` (a non-empty reason) is allowed only under `provider_stages`; run-stage and `serve` refuse a blocked stage except with `--plan-only`. Under `stages` it is refused, because older runners ignore it; block a DeepSeek stage with `paid_allowed: false` and `dry_run_allowed: false`.
- The OpenAI key is read only from a **dedicated key file** given with `--lab-env`, never the lab `.env`: run-stage and `serve` refuse a key file named `.env` or inside a git work tree, because the lab `.env` is loaded by other code with `load_dotenv` and `OPENAI_API_KEY` is the SDKs' default credential.
- `serve --provider openai` needs `--artifact` and `--stage` and applies that stage's `blocked` flag, cap ceilings, request cap, output limits, timeout and models.
- Prices, wire rules, the run plan, the stop rules and the two-sample fidelity rule (`fidelity_rule.py`) are in `../RUN-PLAN-OPENAI.md`; the route smoke is `openai_canary.py` (stage `common/s1-openai-canary`).

**For every provider.** Runner options go before `--`; run-stage refuses `--plan-only`, `--cap-*`, `--lab-env`, `--out-root`, `--dry-run-ollama` and the other runner options after `--` (exit 2), because there they would reach the adapter instead. While a child runs, `common/.run-stage-<pid>-<id>.lock` marks the tree as in use: do not edit `packages/auditor-adapters` while one exists, and launch paid runs from a pinned clean worktree. Every receipt compares code hashes taken before the child started with hashes taken after it ended (`code.launch`, `code.code_changed_during_run`).

## Parts

| Part | What it does |
| --- | --- |
| `load_deepseek_env(lab_env_path)` | Reads only the `DEEPSEEK_API_KEY` line of the lab `.env`; other lines are never decoded. Returns a child env with `OPENAI_BASE_URL=https://api.deepseek.com` and `OPENAI_API_KEY=<key>`. It strips the credentials of other providers (see "Child environment"). Errors never echo the value. |
| `BudgetGuard` | OpenAI-compatible proxy on `127.0.0.1:<ephemeral>`. It holds the real key and accepts only the per-run guard token (details below). |
| `run-stage` | Looks up `<adapter>/stages.json`, checks the CLI caps against the stage ceilings, and starts the guard. It runs the adapter command from a fresh scratch cwd, refusing if any `.env` exists on that cwd or its ancestors. The child sees only the guard URL and the guard token, never the DeepSeek key. The runner kills the child's process tree when the guard halts (after `--grace-seconds`) or times out, then writes `receipt.json`. |
| `require_guard()` | For adapter scripts: returns `(base_url, token)`, or raises unless the process was launched by `run-stage` (or `serve`). |
| `canary_client.py` | Fixed, benign two-request route check (one plain request, one native tool call), run as stage `common/s0-canary`. |
| `openai_canary.py` | OpenAI route smoke over every model id of the OpenAI stages, plus two gpt-5.2 wire probes (stage `common/s1-openai-canary`). |
| `providers.json` | Provider table: base URLs, key names, wire rules, OpenAI prices with sources and fetch date. |
| `fidelity_rule.py` | Two-sample (Newcombe) fidelity rule for published-backbone runs; prints acceptance bands. |
| `postprocess_gate_rows.py` | Zero-cost post-processor of the DeepSeek freeze (`PILOT-PROTOCOL-V1-DEEPSEEK-FROZEN.md` §1.3, §8): reads one run's records (h2, MELON, AttriGuard, ARGUS, PAA or reference format) plus the SS case file and writes every E1–E5 number per seed family (E0B/E1PRE never pooled): per-auditor rates with Wilson and (suite, user task) cluster-bootstrap intervals and per-cluster k/n; executability / value-kind / scope (also by executability) / delegation splits; attacker_attempted and exposure; FACT − INSTR and ASR_d − ASR_0 contrasts; started vs scored denominators; the SS catch (primary per proposal, audited-only secondary, catches without an audit verdict, INSTR+FACT pooled); route shares (AttriGuard AG-H1/AG-H2, MELON T2); attribution (ARGUS blame and `x_action_dep`, PAA blame and AER); false block fail-open and fail-closed; Gate SS-0. One PAA results dir per call. Standard library only; tests in `tests/test_postprocess_gate_rows.py`, plus real-record cross-checks in the AttriGuard, ARGUS, MELON, PAA and reference tests. |

### What the guard does to each request

- Requires `model` to be `deepseek-flash` or a declared alias, then rewrites it to the upstream model.
- Injects `thinking={"type":"disabled"}`.
- Maps `max_completion_tokens` to `max_tokens`, applies a default, and clamps to the stage ceiling.
- Drops OpenAI-only fields (`reasoning_effort`, `parallel_tool_calls`, `store`, ...) and records their names in the ledger.
- Applies the lab adapter's wire normalisation: `developer`→`system`, tool-message `name` dropped, text blocks joined (`agentdojo-lab/src/agentdojo_lab/deepseek_adapter.py:31-44`).
- Answers `/v1/models` locally.
- Refuses `/v1/embeddings`, because DeepSeek has none, unless the stage declares a loopback `local_embeddings` model. Local embeddings are ledgered but do not count toward the caps.

### Caps

A request is refused with HTTP 402, and the guard halts, in any of these cases:

1. The guard is already halted.
2. The stage request cap is reached.
3. **Pre-flight:** spent + in-flight reservations + this request's worst case would exceed `cap_tokens` or `cap_usd`. The worst case is ⌈request bytes / 2⌉ prompt tokens plus `max_tokens × n` completion tokens, so it deliberately overestimates.

After each response the guard charges the provider-reported usage. If the response carries no usage, the guard charges the reservation and halts (`usage_missing`). A transport error after send is charged at the reservation. Upstream HTTP 401, 402 or 403, or 8 consecutive upstream errors, halt the stage.

When the last allowed response reaches a cap, the guard only marks itself halted. The child may finish its own bookkeeping, and the receipt says `completed` with `halt_reason` set. The runner stops the child, after `--grace-seconds`, only once a request has actually been refused for budget reasons or a fatal halt has occurred. That receipt says `halted`.

Cost uses the lab snapshot `deepseek-2026-09-30-conservative-peak-uncached`: $0.30 per M input and $1.20 per M output tokens. Cache hits are charged as misses. Source: `agentdojo-lab/scripts/run_cross_model_technical_pilot_v2.py:74-99`. **These prices were not re-verified on 2026-10-08 (UNVERIFIED).**

## Stage config: `<adapter>/stages.json`

```json
{
  "schema": "auditor-adapter-stages/v1",
  "artifact": "<key>",
  "defaults": { "max_tokens_default": 2048, "max_tokens_ceiling": 4096, "timeout_seconds": 3600, "env": {} },
  "stages": {
    "S1": {
      "argv": ["{artifact_python}", "{adapter_dir}/run_x.py", "--out", "{out_dir}"],
      "cap_usd": 0.25, "cap_tokens": 250000, "cap_requests": 120, "dry_run_cap_requests": 10,
      "model_aliases": ["gpt-4o-mini"],
      "env": { "SOME_API_KEY": "{guard_token}", "SOME_BASE_URL": "{guard_base_url}" },
      "local_embeddings": { "base_url": "http://localhost:11434/v1", "model": "nomic-embed-text" },
      "estimate": { "requests": "...", "tokens": "...", "usd": "..." },
      "compares_to": "..."
    }
  }
}
```

**Caps.** `cap_usd` and `cap_tokens` are ceilings: the runner refuses a CLI `--cap-*` above them. `cap_requests` caps paid runs, and `dry_run_cap_requests` caps Ollama runs.

**Env values.** An env value whose name ends in `_API_KEY`, `_TOKEN`, `_SECRET` (and similar) may only be `{guard_token}`. A URL-like name may only be `{guard_base_url}` or a loopback URL.

**Keys.**
- Known keys: `description`, `argv`, `cap_usd`, `cap_tokens`, `cap_requests`, `dry_run_cap_requests`, `model_aliases`, `request_model`, `max_tokens_default`, `max_tokens_ceiling`, `request_timeout_seconds`, `timeout_seconds`, `env`, `venv`, `local_embeddings`, `paid_allowed`, `dry_run_allowed`, `estimate`, `compares_to`, `fidelity`; for `provider_stages` also `provider`, `models` and `blocked` (see "Providers").
- Any other key is treated as metadata and reported as ignored.
- An unknown key that looks like a typo of a safety key (`cap_*`, `max_tokens*`, `model_alias*`, `dry_run*`, ...) is refused.

**Placeholders.**
- Built in: `{python}` (the runner's interpreter), `{artifact_root}`, `{artifact_python}` (`<artifact_root>/<venv>/Scripts/python.exe`), `{adapter_dir}`, `{common_dir}`, `{out_dir}`, `{cwd}`, `{model}`, `{mode}`, `{artifact}`, `{stage}`, `{guard_base_url}`, `{guard_token}`.
- Add more with `--set name=value`.
- Never put machine-specific absolute paths in `stages.json`; pass them as `--artifact-root`, `--set`, or the env vars `AUDITOR_ARTIFACTS_ROOT`, `AUDITOR_LAB_ENV` and `AUDITOR_OUT_ROOT`.

## Child environment

**Removed:**
- names starting with `OPENAI_`, `ANTHROPIC_`, `GOOGLE_`, `TOGETHER_`, `HF_`, `GROQ_`, `GEMINI_`, `COHERE_`, `MISTRAL_`, `AZURE_OPENAI_`, `VERTEX`, `GCP_`, `AWS_`, `DEEPSEEK_`, `LANGCHAIN_`, `LANGSMITH_`, `WANDB_` (and a few more);
- any name ending in `_API_KEY`, `_TOKEN` or `_SECRET` (and similar).

**Set:**
- `OPENAI_BASE_URL` and `OPENAI_API_BASE` = guard URL;
- `OPENAI_API_KEY` = guard token;
- `AUDITOR_GUARD_URL`, `AUDITOR_GUARD_TOKEN`, `AUDITOR_ARTIFACT`, `AUDITOR_STAGE`, `AUDITOR_MODE`, `AUDITOR_OUT_DIR`, `AUDITOR_REQUEST_MODEL`, `AUDITOR_BACKBONE`;
- `NO_PROXY` for loopback;
- `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`;
- `PYTHONUTF8=1`.

## Commands

Run these from `packages/auditor-adapters`. Use an artifact venv python when the stage needs that venv's packages.

```powershell
# Unit tests (fake loopback upstreams only; no network)
python -m unittest discover -s common/tests -v

# Resolve and print a stage without starting anything or reading the key
# (--plan-only goes before any "--"; after it, run-stage refuses it)
python common/deepseek_route.py run-stage --artifact common --stage s0-canary --cap-usd 0.01 --cap-tokens 5000 --out-root <out> --plan-only

# Plumbing dry run against local Ollama (qwen2.5:7b-instruct); never reads the key
python common/deepseek_route.py run-stage --artifact common --stage s0-canary --cap-usd 0.01 --cap-tokens 5000 --dry-run-ollama --out-root <artifact smoke dir>

# Paid route canary, once DEEPSEEK_API_KEY is in the lab .env (2 requests, hard cap $0.01)
python common/deepseek_route.py run-stage --artifact common --stage s0-canary --cap-usd 0.01 --cap-tokens 5000 --lab-env <agentdojo-lab/.env> --out-root <results checkout>/auditor-adapters
```

**Output location.** `--out-root` must be outside this code repository. Use the artifact's `smoke/` directory for dry runs. Use the private results checkout for paid runs, after the path handshake in the repository `AGENTS.md`.

**Run directory.** Each run writes `<out-root>/<artifact>/<stage>/<UTC stamp>-<mode>[-label]/`, containing:
- `ledger.jsonl`
- `receipt.json`
- `child_stdout.txt` and `child_stderr.txt`
- the scratch `cwd/`

**Exit codes.**

| Code | Meaning |
| --- | --- |
| 0 | completed |
| child's own code | child failed |
| 2 | refused configuration (including a runner option placed after `--`) |
| 3 | halted by the guard |
| 4 | timeout |
| 5 | launch failed |

## Ledger and receipt

Each `ledger.jsonl` line (`auditor-guard-ledger/v1`) holds **ids, counts and usage only, never prompt or completion text**. Its fields:
- `seq`, `request_id`, `upstream_id`, `endpoint`, `outcome` (`ok`, `refused`, `upstream_error`, `transport_error`), `refusal`, `http_status`;
- `requested_model` and `upstream_model`;
- `max_tokens` and whether it was clamped, `dropped_fields`, normalisation counts, message and tool counts;
- `request_sha256` of the forwarded body;
- `finish_reason`;
- provider `prompt_tokens`, `completion_tokens`, cache-hit and cache-miss tokens, `usage_source` (`provider` or `estimate`);
- the pre-flight estimate;
- `usd`, cumulative usage and USD, and the halt state.

`receipt.json` (`auditor-stage-receipt/v1`) records:
- status, exit code, resolved argv (token redacted), scratch cwd;
- names of the env variables added and stripped;
- caps and stage ceilings, the guard summary, the price snapshot;
- ledger sha256 and line count;
- the agent-tracer commit, adapter dirty state, sha256 of `deepseek_route.py` and of the stage config, taken when the receipt is written;
- `code.launch`: the same hashes plus an adapter-tree hash, taken before the child started; `code.deepseek_route_sha256_at_import`; `code.code_changed_during_run` with the changed keys and files; the run's lock file;
- the runner Python;
- the fidelity label: `backbone-substituted (deepseek-flash)`, or `plumbing dry run only (not evidence)` for Ollama.

## Known limits

- **Pre-flight overestimate.** The estimate uses 2 bytes per token. Measured on the dry run, it overestimated prompt tokens by 1.3–4×, so the last request before a cap can be refused early. Set caps with headroom.
- **Concurrency.** Concurrent in-flight reservations can also halt a stage early. This is conservative.
- **Failed requests.** Upstream 4xx/5xx responses are charged $0, on the assumption that the provider does not bill failed requests (UNVERIFIED). Transport errors after send, and streams that break before usage arrives, are charged at the reservation.
- **Clamping.** `max_tokens` clamping and dropped fields change the artifact's request. Both are ledgered and must be declared as deviations.
- **Model list.** `/v1/models` is synthetic, and the first id is always `deepseek-flash`.
- **Dry-run cost.** Ollama dry runs use the same price for a *notional* USD (`usd_is_notional: true`), so cap logic is exercised identically. They are plumbing checks, never evidence.


## ADI-derived case files (amendment `authority-auditor-pilot-v1-deepseek.1`)

**Status.** Loader, exporter and stage support for the versioned amendment `authority-auditor-pilot-v1-deepseek.1`
(the frozen id pattern `...-deepseek.<n>`) to the frozen DeepSeek protocol (agent-tracer f87b847; freeze record in
results commit 7706321f). The amendment is **PROPOSED** (`../agentdojo-lab/PILOT-PROTOCOL-V1-DEEPSEEK-AMENDMENT-1.md`,
`../agentdojo-lab/configs/pilot_protocol_v1_deepseek_amendment_1.json` = ACFG, `../DEEPSEEK-FREEZE-V1-AMENDMENT-1.md`).
The user decided on 2026-10-09 that the A1 stratum uses the 19 ADI authority cases (our classification of the published
ADI syntactic cases, drawn during the D03 verification; arXiv:2607.05120; github.com/compsec-snu/adi, MIT, commit
1a3ddf8). It was made **after seeing data** (ACFG `data_seen_before_amendment`: D01-D07 with D03, the ADI baseline,
and existing batch-2 output; the data-read statement U4 is open), so everything run under it is exploratory and not
pre-registered, and ADI-derived rows are never compared with D03's 7/19 or ADI's 53/108. Nothing here authorizes a run:
G-ADI-0 (U1-U4 signed, the amendment committed, batch 2 finished, the gates below) comes first. The frozen SS stages,
configs and outputs are unchanged: every ADI stage lives in a separate `<adapter>/stages.adi.json` (with its own runner
config where the runner has one), and an SS file runs as before.

**What the loaders accept** (on top of the common contract `h2-cases/v2`, `../agentdojo-lab/H2-CASES-V1.md` section 8):

- a top-level `tool_output_format`: `"yaml"` or `"json"`; absent means `"yaml"` (stock AgentDojo 0.1.35
  `tool_result_to_str`, the behaviour of every SS run). Any other value is refused when the file is loaded.
  `"json"` means the ADI fork's formatter, `common/adi_compat.adi_tool_result_to_str`: `json.dumps` of
  `model_dump(mode='json')`, ASCII escapes. It is **copied with attribution** from compsec-snu/adi @ 1a3ddf8
  `agentdojo/src/agentdojo/agent_pipeline/tool_execution.py` lines 22-48 (MIT; the notice is in the file), because the
  fork's package is also named `agentdojo` and cannot be imported next to the vendored 0.1.35. The only change is that
  `pydantic.BaseModel` is imported inside the function. Tested: the body equals the fork's statement for statement
  (AST), and in the fork's own venv both give identical text on 8 tool outputs of the fork's banking, workspace and slack
  suites (`common/tests/test_adi_compat.py`). Stock 0.1.35's own `tool_output_format="json"` is not used: it dumps
  `model_dump()` without `mode='json'` and fails on datetimes;
- cases of `seed_family` `"ADI"` with arms `"ATTACK"` (the ADI payload; an X-carrying, steering arm) and `"CLEAN"`
  (benign; `injections` `{}`, the stock defaults). A plan or selection that mixes ADI with any other family is refused
  (`adi_compat.check_family_mix`), so no adapter summary pools ADI with E0B or E1PRE, and the post-processor reports ADI
  as its own group;
- **a per-arm legitimate set** (`arms[arm].legitimate_set`, ADI-X-11): in slack ut9[0], ut10[0] and ut19[0] the
  legitimate External channel of ATTACK (`'External_' + payload`) differs from CLEAN's (`External_0`). h2 (and so MELON
  and PAA, which read the h2 plan), AttriGuard, ARGUS (each unit's oracle) and the reference spec read the arm's own set
  where it is given (`adi_compat.arm_legitimate_set`); the case-level `legitimate_set` is the union of both arms (safe:
  neither value exists in the other arm's environment). The ATTACK value is built from payload text: cite it by the
  hash in the case's `adi.legitimate_sha256`;
- `split` (the ADI stages select `dev` only: the frozen eval protection, PROT 8.4), `substratum` (post-processor subsets
  `substratum=<label>`), `design.argus_span_separated` (below) and `gt.attacker_executable` true or false. An ADI case
  whose executability is still null is **refused** by h2, AttriGuard and ARGUS before anything runs (the exporter
  resolves an 'untested' entry at G-ADI-CONF); the post-processor's `executable=untested` subset stays as a guard.

`injections` values are the exact strings every runner passes to the stock `suite.load_and_inject_default_environment`;
the loaders never transform payload text, and `arm_text` is the payload as the environment holds it after YAML parsing.
Case files with payloads are generated outside the repo into the results checkout; every ADI stage takes the file as
`--set cases=<path>` and pins it with `--set cases_sha256=<sha256 of the file with CRLF normalised to LF>`
(`adi_compat.sha256_lf`). A wrong or missing pin is refused before any request.

**Where the formatter is applied** (agent and auditor read the same text in every adapter):

| Adapter | How |
| --- | --- |
| h2 (undefended) | `run_h2.build_runtime(..., tool_output_format=)` sets `output_formatter` on the pipeline's one `ToolsExecutor` |
| MELON | the child passes the case file's format to the same `build_runtime`; MELON reads the tool messages that executor wrote (original and masked runs) |
| AttriGuard | runtime adapter, no artifact edit: the release hard-codes `tool_output_format=None`; the runner replaces the formatter of the `no_defense` ToolsExecutor and of the gate's `tools_executor` (used for audited and unaudited executions), then reads it back |
| ARGUS | runtime adapter: `argus_gate.use_tool_output_format` rebinds Warrant's module-level `tool_result_to_str` (`agentlure.warrant.auditor`) and the `none` row's ToolsExecutor; span mapping reads `\uXXXX` |
| PAA converter | locates components and values in a JSON-unescaped view of the recorded outputs (the YAML view for yaml) |
| reference | native replays (`native_replay.scripted_trace`) render with the case file's formatter; value matching already decodes JSON scalars |

**Exposure (M2).** For an ADI episode, h2's `injection_exposed` is the ATTACK payload (its `arm_text`, raw or
JSON-escaped) seen in a tool output, None for CLEAN; X in a tool output is the separate
`attacker_value_in_tool_output`, because X is native in the A1mech and Xboth cases and that test is almost always true.
The plan carries the needle (`exposure_needles`) for ADI episodes only, so SS plans are unchanged. MELON, AttriGuard and
ARGUS already test the arm text; under json every needle is also tried JSON-escaped, and the secondary X test also
reads the JSON-unescaped output (`adi_compat.value_in_outputs`), so X right after an escape such as a newline is found.
The native post-state count of X uses `adi_compat.state_needle(X)` (identical to X for every SS value).

### The exporter and the conformance gate (G-ADI-EXPORT, G-ADI-CONF)

`common/adi_export.py` (lab venv) with its fork side `../adi/adi_export_fork.py` (the ADI artifact venv), zero model
requests, each process behind its own loopback-only network guard:

```powershell
& $PY "$AT/packages/auditor-adapters/common/adi_export.py" export --acfg $ACFG `
  --frozen-config "$LAB/configs/pilot_protocol_v1_deepseek_frozen.json" `
  --ss-cases "$RES/experiments/20261009-authority-auditor-pilot-v1-deepseek-freeze/config/h2_cases_v1.generated.json" `
  --fork-python "$EXT/adi/.venv/Scripts/python.exe" --fork-src "$EXT/adi/src" `
  --argus-segmentation "$EXT/argus/src/AgentLure/agentlure/warrant/segmentation.py" --out $ADICASES
& $PY "$AT/packages/auditor-adapters/common/adi_export.py" verify --acfg $ACFG --cases $ADICASES --expect-sha256 $ADISHA
```

- **Fork side.** Checks the fork checkout is at the pinned commit with a clean tree (git), then imports the fork's
  `INJECTED_DATA_SYNTACTIC` (each payload verbatim; nothing retyped) and its `task_suite._escape_yaml_value` (imported, not
  copied), checks every payload, canonical-injection and X hash against ACFG `case_table[].expected_hashes`, and records
  the fork's own ground-truth tool outputs. Its output (`fork_reference.json`) holds payload text and is refused inside
  the repository.
- **Stock port and G-ADI-CONF**, per case: the vectors exist in stock v1.2.2 (no fork data are overlaid, ADI-X-3); the
  stock environment holds the payload as the fork's does; the ground-truth tool outputs rendered with the JSON formatter
  equal the fork's **byte for byte**; the ground-truth legitimate value of each arm equals the table; **both arms'**
  ground truth score `legitimate` with utility true; X-substitution executability (the SS generator's rule, on the
  ATTACK environment) equals the table or resolves an 'untested' entry; the state-observable flag uses the runners'
  counting rule; the split is re-derived (ADI-X-9) and must equal the table. A failing case is written with
  `invariants.all` false (never selected) and its reason. Both sides run the ground truth with `PYTHONHASHSEED=0` and
  the suite tools' run-time clock frozen at one instant (`adi_compat.frozen_tool_clock`; `append_to_file`,
  `create_file` and `send_email` stamp `datetime.now()`, and calendar `create_event` orders participants through a set),
  so every other byte must be equal (ADI-X-13; runs freeze nothing).
- **Recorded, not gating:** the payload seen before the sink, native X before the sink, whether a source-level carrier
  is separable (it is not in any stock-expressible case: native X and the payload share a tool output, so no
  `carrier_tools` are declared and the reference carrier readings stay content-derived), and the Warrant span check
  (ADI-X-12): under the JSON rendering Warrant's line-based partition puts the payload and the native X of the slack
  `get_channels` output into one span for slack ut9[0], ut10[0] and ut19[0] (under YAML they are apart); workspace ut35[0]
  and ut38[2] are separated under both. The case carries `design.argus_span_separated`; the post-processor leaves the
  ARGUS attribution items of such a case out and counts them in `attribution.argus_blame_undefined_span_shared`.
- **Outputs.** The case file (deterministic: re-exporting reproduces its LF sha256), `<file>.sha256`, and
  `adi_export_report.json`, which is scanned for 24-character payload shingles before it is written. `verify` re-checks
  a written file against ACFG without the fork (hashes recomputed from `arm_text`, split, sub-stratum, per-arm sets).

**Scratch export of 2026-10-09** (`D:/Jerry/external-auditors/_adi_a1/fix_loaders/export/`, not a run input):
G-ADI-EXPORT passes (19/19 hashes); G-ADI-CONF as written fails 7 of 19: the 3 fork-only-vector cases; slack ut18[2]
and ut18[3] (eval; the fork's `get_webpage` text has one extra leading space); and workspace ut35[0] and ut38[2] (dev,
both A1mech; `list_files` differs in 2 characters, the fork's typo fix in another file's `shared_with`,
`cloud_drive.yaml:666-667`, touching neither the payload nor X). Eligible: 12 (6 dev: slack ut5[0], ut5[1], ut9[0],
ut19[0], workspace ut8[0], ut29[0]; A1mech 0, Xboth 3, Xatt 3). Whether to tolerate differences that touch neither the
payload nor X (recorded per case as `invariants.gt_outputs_differ_only_outside_payload`) is a decision for a further
amendment item, not this code.

### Stages (G-ADI-STAGES)

ACFG `experiments[]` is the single source of every ADI stage's cap and run block. `common/adi_stages.py write`
generates the caps, repeats, max_cases and PAA unit/request caps of the stage files from it; `check` lists every
difference (G-ADI-STAGES holds when it is empty; it also checks that the frozen `argus/stages.json` AL-S2-ADI keeps
`paid_allowed: false` and that ARGUS ADI-S2 stays under its ceiling); `plan` resolves every stage through the route at
the ACFG caps with `plan_only` (no guard, no key). `common/tests/test_adi_stages.py` asserts all three. Selection:
dev-split ADI cases with `invariants.all` true; ADI-S1 the first 3 in case-file order x 1 repeat; ADI-S2 all of them;
ATTACK and CLEAN. h2, MELON, AttriGuard: 5 repeats at T=0.7. ARGUS: 2 repeats at the artifact's temperature (ADI-X-8;
no `--agent-temperature`), 1 under the pre-registered Gate S1-ADI fallback.

| ID | Adapter | Stage | Cap USD / tokens / requests | Guard est. (ACFG) |
| --- | --- | --- | --- | --- |
| D23 | h2 | ADI-S1 | 0.10 / 300k / 200 | <= 0.02 |
| D24 | MELON | ADI-S1 | 0.25 / 600k / 400 | <= 0.09 |
| D25 | AttriGuard | ADI-S1 | 0.40 / 1M / 800 | <= 0.20 |
| D26 | ARGUS | ADI-S1 | 1.00 / 3M / 3,000 | <= 0.90 |
| D27 | h2 | ADI-S2 | 1.00 / 2.5M / 3,200 | 0.20-0.49 |
| D28 | MELON | ADI-S2 | 2.60 / 6.5M / 4,000 | 0.66-1.30 |
| D29 | AttriGuard | ADI-S2 | 5.30 / 13.5M / 4,800 | 1.24-2.61 |
| D30 | ARGUS | ADI-S2 | 6.50 / 20M / 16,000 | 2.08-5.97 |
| D31 | PAA | ADI-S1 | 0.50 / 1M / 48 (8 units) | <= 0.39 |
| D32 | PAA | ADI-S2 | 6.50 / 13M / 774 (129 units) | 1.60-6.29 |

Total **$24.15** guard USD, the amendment's proposed U3 figure (not yet signed). Cost basis: ACFG `cost_basis` only
(every estimate UNVERIFIED), with its D05-D07 cross-check (`cost_basis.cross_check_d05_d07`: measured MELON 1.39x,
AttriGuard 3.07x per 2-row stimulus, ARGUS 28.1x per 2-row stimulus with Warrant 10.0x the none row; each at or below
the high ratio used). The caps assume 8 dev cases; under the scratch conformance result 6 run (60 h2 episodes), so the
caps are not binding upward. If the user signs other figures, change ACFG and run `adi_stages.py write` then `check`.

Run order (one paid stage at a time), post-processing and the commands per experiment: `../DEEPSEEK-FREEZE-V1-AMENDMENT-1.md`
sections 5 and 6. Post-process each run with `postprocess_gate_rows.py --protocol-config $ACFG` (groups `ADI|...`; the
scope and flag subsets read `threat_model.adi_case_scope`; Gate SS-0 is not computed for an ADI-only run).
