# Shared DeepSeek route and budget guard

`deepseek_route.py` lets every third-party auditor adapter run with DeepSeek (`deepseek-flash`) as its only paid backbone, under a hard per-stage budget. It uses only the standard library (Python 3.10 or later), so it runs inside each artifact's own venv.

DeepSeek is also the common backbone for the cross-auditor comparison (pilot protocol OPEN-3). The published fidelity targets used other backbones, so every DeepSeek run is labelled **backbone-substituted**. It is a fidelity check, not an exact reproduction.

## Parts

| Part | What it does |
| --- | --- |
| `load_deepseek_env(lab_env_path)` | Reads only the `DEEPSEEK_API_KEY` line of the lab `.env`; other lines are never decoded. Returns a child env with `OPENAI_BASE_URL=https://api.deepseek.com` and `OPENAI_API_KEY=<key>`. It strips the credentials of other providers (see "Child environment"). Errors never echo the value. |
| `BudgetGuard` | OpenAI-compatible proxy on `127.0.0.1:<ephemeral>`. It holds the real key and accepts only the per-run guard token (details below). |
| `run-stage` | Looks up `<adapter>/stages.json`, checks the CLI caps against the stage ceilings, and starts the guard. It runs the adapter command from a fresh scratch cwd, refusing if any `.env` exists on that cwd or its ancestors. The child sees only the guard URL and the guard token, never the DeepSeek key. The runner kills the child's process tree when the guard halts (after `--grace-seconds`) or times out, then writes `receipt.json`. |
| `require_guard()` | For adapter scripts: returns `(base_url, token)`, or raises unless the process was launched by `run-stage` (or `serve`). |
| `canary_client.py` | Fixed, benign two-request route check (one plain request, one native tool call), run as stage `common/s0-canary`. |

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
- Known keys: `description`, `argv`, `cap_usd`, `cap_tokens`, `cap_requests`, `dry_run_cap_requests`, `model_aliases`, `request_model`, `max_tokens_default`, `max_tokens_ceiling`, `request_timeout_seconds`, `timeout_seconds`, `env`, `venv`, `local_embeddings`, `paid_allowed`, `dry_run_allowed`, `estimate`, `compares_to`, `fidelity`.
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
| 2 | refused configuration |
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
- the agent-tracer commit, adapter dirty state, sha256 of `deepseek_route.py` and of the stage config;
- the runner Python;
- the fidelity label: `backbone-substituted (deepseek-flash)`, or `plumbing dry run only (not evidence)` for Ollama.

## Known limits

- **Pre-flight overestimate.** The estimate uses 2 bytes per token. Measured on the dry run, it overestimated prompt tokens by 1.3–4×, so the last request before a cap can be refused early. Set caps with headroom.
- **Concurrency.** Concurrent in-flight reservations can also halt a stage early. This is conservative.
- **Failed requests.** Upstream 4xx/5xx responses are charged $0, on the assumption that DeepSeek does not bill failed requests (UNVERIFIED). Transport errors after send are charged at the reservation.
- **Clamping.** `max_tokens` clamping and dropped fields change the artifact's request. Both are ledgered and must be declared as deviations.
- **Model list.** `/v1/models` is synthetic, and the first id is always `deepseek-flash`.
- **Dry-run cost.** Ollama dry runs use the same price for a *notional* USD (`usd_is_notional: true`), so cap logic is exercised identically. They are plumbing checks, never evidence.
