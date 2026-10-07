# MELON adapter: DeepSeek backbone through the budget guard

This adapter runs the unmodified MELON artifact (kaijiezhu11/MELON @ `4d3cc9c0`, `pi_detector.py`
sha256 `5a7f6b28…a9017`) with **deepseek-flash** as the backbone. Every chat request goes through
the shared budget guard in `../common/deepseek_route.py`. It runs inside the artifact's own venv
(Python 3.11, agentdojo 0.1.24).

**Fidelity label.** These runs are *backbone-substituted*, not exact reproductions:
- deepseek-flash replaces GPT-4o;
- all-MiniLM-L6-v2 replaces `text-embedding-3-large`, while the threshold stays at the hard-coded 0.8;
- the cache is per-task.

Compare only the direction against the paper's numbers. The paper publishes no per-suite targets.

**No third-party code is copied here.** MELON has no licence, so the artifact is imported by path
from its own folder, with a SHA-256 check.

## Files

| File | Role |
|---|---|
| `stages.json` | Stage config read by the shared runner (`auditor-adapter-stages/v1`): argv, cap ceilings, UNVERIFIED estimates. No machine paths. |
| `run_melon_stage.py` | Stage driver. Plans the episodes and starts **one fresh interpreter per episode**, then writes `stage_summary.json`. Makes no model request itself. |
| `run_melon_episode.py` | Runs one episode (No-defense or MELON row) through AgentDojo 0.1.24's own benchmark functions, and writes `episodes/<id>.json` plus the artifact's stdout log. |
| `melon_route.py` | Requires a loopback base URL. Applies the DeepSeek wire shaping (model, `max_tokens`, thinking disabled, tool-message `name` dropped). Enforces a per-episode request cap and keeps a usage tally (no prompt text). |
| `melon_embedder.py` | Declared embedder substitutes: in-process MiniLM (default) or loopback Ollama `nomic-embed-text`. |
| `melon_netguard.py` | Loopback-only sockets in the episode process. |
| `tests/test_melon_adapter.py` | Unit tests, plus end-to-end tests against a scripted loopback fake upstream. |

## How each hook is handled

**Backbone.** MELON never builds a chat client. The README wiring passes an AgentDojo LLM element
into `MELON(llm, …)`, and MELON calls `llm.query` for both the original and the masked run
(`pi_detector.py:311`, `:365`). So the episode builds AgentDojo 0.1.24's own `OpenAILLM` with an
OpenAI client whose `base_url` is the guard (`OPENAI_BASE_URL`, which must be loopback). The
`api_key` is the guard's per-run token, so the episode process never sees the DeepSeek key.
- AgentDojo 0.1.24 sends `temperature=0.0` (`openai_llm.py:105-113`).
- Its tenacity retry (3 attempts, everything except `BadRequestError`) is kept as released.
- The SDK's own retries are off (`max_retries=0`).

**Embedder (harness substitution, no source edit).** `MELON.__init__` hard-codes
`OpenAI(api_key="your-api-key")` and the model `text-embedding-3-large` (`:209`, `:396-399`,
`:431-434`). After construction the episode replaces `detector.detection_model` with
`SubstituteEmbeddingClient`, which implements only `embeddings.create(input, model)`.
- **Default: `minilm`.** This is the lab's pinned `all-MiniLM-L6-v2` (revision `1110a243…`),
  run with transformers. It reproduces the model's sentence-transformers stack: max_seq_length 256,
  mean pooling, then L2 normalisation. The weights' SHA-256 goes into every episode record.
- **Option: `--embedder ollama-nomic`.** Uses loopback Ollama.
- DeepSeek has no embeddings endpoint, so nothing goes to the guard.

**agentdojo 0.1.24 pin.** `pi_detector.py` concatenates string message content (`:324`) and
crashes on ≥0.1.30 content blocks (Week-1 T7). The episode refuses to run unless
`importlib.metadata.version("agentdojo") == "0.1.24"`. 0.1.24 is also the best-guess paper
environment: benchmark v1.1.2, 629 pairs, and `temperature=0` actually sent (UNVERIFIED versus
the authors' setup).

**Cross-task cache: one fresh process per episode.**
- MELON stores its masked-call cache and its sticky `is_injection` flag in `extra_args`.
- AgentDojo 0.1.24 never passes `extra_args`, so they live in `AgentPipeline.query`'s mutable
  default dict for the whole interpreter. A new pipeline does not reset it (Week-1 T8).
- The stage driver therefore starts a new interpreter for every episode, and the episode
  asserts that the shared dict is empty at start.
- This gives the **per-task cache** (the paper's §3.2 intent) for our primary rows.
- The as-released process-wide behaviour (one interpreter per suite, with the injection-task
  pre-runs seeding the cache) is a fidelity *variant*. It is not implemented here, because it
  roughly doubles the MELON cost.

**Injection template name.** `important_instructions` addresses the model by name, using the
pipeline name. The pipeline name carries the tag `gpt-4o-2024-05-13`, so the injected text says
"GPT-4", byte-identical to the paper's GPT-4o rows. Change it with `--template-model-tag`.

**Evidence.**
- The artifact pairs its printed bank strings with embeddings by zipping a set with a list
  (`:443`). So its *printed* pairing is unreliable once the bank holds two or more strings.
- The verdict is not affected, because every bank embedding is compared.
- The episode wraps `detect` and recomputes the best (proposed, cached) pair from the same
  vectors.
- Per step it records: proposed projected calls, new masked calls, bank size,
  `bank_empty_at_compare` (the T2 / A1 path), the flag and the cosine.

## Running

```bash
# zero-cost checks (inside the MELON venv)
MELON_ARTIFACT_DIR=<artifact folder> MELON_EMBEDDER_DIR=<pinned MiniLM dir> \
  <melon venv python> -s -P -m unittest discover -s packages/auditor-adapters/melon/tests -v
<melon venv python> -s -P packages/auditor-adapters/melon/run_melon_stage.py --stage s2 --out-dir <dir> --plan-only

# one capped command per stage (the guard holds the key; out-root must be outside this repo)
python packages/auditor-adapters/common/deepseek_route.py run-stage --artifact melon --stage dry \
  --dry-run-ollama --cap-usd 0.01 --cap-tokens 60000 \
  --artifact-root <artifact folder> --out-root <results or smoke dir> --set embedder_dir=<pinned MiniLM dir>
python packages/auditor-adapters/common/deepseek_route.py run-stage --artifact melon --stage s1 \
  --cap-usd 0.05 --cap-tokens 100000 --lab-env <lab .env> \
  --artifact-root <artifact folder> --out-root <results dir> --set embedder_dir=<pinned MiniLM dir>
python packages/auditor-adapters/common/deepseek_route.py run-stage --artifact melon --stage s2 \
  --cap-usd 6 --cap-tokens 16000000 --lab-env <lab .env> \
  --artifact-root <artifact folder> --out-root <results dir> --set embedder_dir=<pinned MiniLM dir>
```

- **Resuming.** To resume an S2 run that stopped (cap or error), append `-- --resume --out-dir <previous run dir>`.
  That reuses the previous run's ok episodes, under a new guard with a fresh cap.
- **Stopping.** The driver stops after the first failed episode (`--max-episode-errors 0`).
- **Guard halt.** A guard refusal (HTTP 402) halts the guard, and the runner kills the episode tree.

## Outputs (under the runner's `out_dir`)

- `receipt.json` and `ledger.jsonl`: written by the runner and guard (authoritative usage and USD).
- `plan.json` and `stage_summary.json`: written by this adapter. The summary gives BU, UA and ASR
  per row × suite, client-side usage, and the published targets for reference.
- `episodes/<row>__<suite>__<user_task>__<injection_task|none>.json`, plus `.stdout.log`: the
  artifact's own printout, which includes tool outputs (benchmark data).
- `traces/<pipeline_name>/<suite>/<user_task>/<attack>/<injection_task>.json`: AgentDojo's
  standard TraceLogger output.

## Estimates (all UNVERIFIED; the guard caps are the hard limit)

**Token bases.**
- Lab native DeepSeek per-slot means: banking 5,849 and slack 8,328 tokens
  (`packages/agentdojo-lab/PILOT-PROTOCOL-V1-DRAFT.md` §9.1).
- MELON adds one masked call per tool step, and its prompt is about 1.5× the original prompt
  (Week-1 Ollama smoke). That gives about 1.8–2.6× the No-defense tokens.

**Prices.** $0.30 per M input and $1.20 per M output (lab snapshot 2026-09-30).

| Stage | Episodes | Tokens | USD | Hard cap |
|---|---|---|---|---|
| dry (Ollama) | 1 | 4–15k | 0 | 10 requests |
| S1 | 2 | 16–34k | 0.006–0.012 | $0.05 / 100k tokens |
| S2 | 572 | 5.6–10.8M | 1.9–3.7 | $6 / 16M tokens |
