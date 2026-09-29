# Live provenance: frozen implementation and validation protocol

## Material Passport

- Origin Skill: academic-research-suite, continuing the existing project research protocol
- Origin Mode: engineering implementation and prospective validation
- Origin Date: 2026-09-08
- Verification Status: acceptance protocol frozen; execution results must be recorded separately
- Version Label: online-provenance-v1
- Evidence Class: observational engineering validation, not independent provenance ground truth

This milestone attaches the existing source-candidate components to a running AgentDojo agent. It must
finish and flush each successful call analysis before that call enters the observed tool runtime. It does
not update model weights, change primary requests or actions, block tools, or introduce CTTA. Exact
matching, LCS, and optional semantic comparisons remain evidence components rather than safety verdicts.

This document defines the acceptance conditions before interpreting the new run. Record the source
revision, dependency-lock hash, this document's hash, commands, artifact paths, and actual results in a
separate execution record. Preserve failures and deviations. Do not turn a pending criterion into a
completed result by editing its definition after observing the run.

## Interface and fixed method scope

Live attribution is opt-in:

```bash
.venv/bin/dojo-lab run --config configs/groq.toml --task user_task_20 \
  --online-provenance
```

Without semantic options, this enables the existing exact and Tier 2 LCS components. Optional Tier 3 and
Tier 4 components require both a local model directory and its full pinned revision:

```bash
HF_HUB_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 \
  .venv/bin/dojo-lab run --config configs/groq.toml --task user_task_20 \
  --online-provenance \
  --semantic-model .model-cache/all-MiniLM-L6-v2-1110a243 \
  --semantic-revision 1110a243fdf4706b3f48f1d95db1a4f5529b4d41
```

The second command uses Groq for the agent and local MiniLM for attribution. Model download is a separate
setup step, not part of this command. The output run directory must be new; omitting `--output` lets the
runner create one. Local credentials stay in the existing local configuration and must not be copied into
reports. `--no-record` is incompatible with online attribution. Semantic options without online attribution,
an unmatched model/revision option, or an invalid local snapshot must fail preflight before an agent request.

| Component | Frozen choice |
| --- | --- |
| Source boundary | Text parts present in the actual outbound request for the current proposal |
| Tool visibility | A matching, earlier tool result and validated exposure in that request |
| Target unit | Each JSON leaf argument; retain array indices and RFC 6901 argument pointers |
| Source identities | Keep user, system/developer, assistant, and tool sources separate |
| Exact / LCS | Existing `exact_v1` and `nt_style_lcs_v1`, with their recorded limits and statuses |
| Semantic model | `sentence-transformers/all-MiniLM-L6-v2` |
| Semantic revision | `1110a243fdf4706b3f48f1d95db1a4f5529b4d41` |
| Model verification | Required local files must match the packaged SHA-256 pin manifest |
| Encoder | CPU, float32, native pooling, normalized embeddings, 256-token limit |
| Tier 3 / Tier 4 | Existing whole-text and chunked components; cosine 0.60, coverage 0.10 |
| Chunking | Existing three-sentence chunks with one-sentence overlap and recorded encoding spans |
| Comparison policy | Each enabled component independently evaluates every eligible source/argument pair |
| Runtime policy | Synchronous callback; no early-exit cascade and no hard analysis deadline |

The component definitions, truncation handling, caches, and resource limits remain those documented in
[PROVENANCE.md](PROVENANCE.md) and [SEMANTIC.md](SEMANTIC.md). This milestone changes when they run, not
their scoring rules. It does not implement a complete NeuroTaint cascade or tune thresholds on this run.

## Observation boundary and record order

The recorder first serializes a detached event snapshot, redacts configured credentials, writes the primary
event line, and flushes it. Only after that succeeds does it pass a separate decoded copy to the subscriber.
The subscriber must never receive a live reference to agent state, unredacted payloads, or an event whose
primary write failed. Mutating the callback copy must not mutate the agent or the already written event.

The incremental tracker consumes these observations in order. At `TOOL_CALL_PROPOSED`, it uses only the
request prefix associated with that proposal. Multiple calls proposed in one model response share that
request's visible sources; a result from the first call cannot become a source for another call in the same
response. A later request may expose that result and make it available for later proposals.

Keep primary observation and attribution in separate files:

| Artifact / record | Purpose |
| --- | --- |
| `events.jsonl` | Existing primary observations, with unchanged payload semantics |
| `provenance.jsonl`: `call_analysis` | Proposal identity, request boundary, source snapshots, leaf fields, enabled component results, and compute timing |
| `provenance.jsonl`: `analysis_flush` | A receipt identifying a successfully flushed analysis and its flush timing |
| `provenance.jsonl`: `runtime_timing` | A link between the relevant analysis/flush and the captured runtime-entry boundary |
| `manifest.json` | Enabled mode, run configuration, semantic model identity, implementation hashes, and timing scope |
| `summary.json` | Primary agent outcome and a separate attribution completeness/error summary |

The successful sequence is: primary proposal flush, analysis computation, analysis write/flush, flush
receipt, then the corresponding observed runtime-entry event. A proposal rejected before runtime still
requires an analysis; it does not acquire an invented runtime entry. A multi-call response may produce
several analyses before any of its calls execute. Join records by run and explicit call/proposal identities,
not by the nearest preceding line or a presumed alternating model/tool sequence.

Here, flush means completion of the file stream's flush operation. It is not an `fsync` or a guarantee of
survival after power loss. Do not describe a flush receipt as stronger storage durability than is measured.

## Timing and failure contract

Model verification and local model loading happen during preflight, before the agent elapsed-time clock
starts. Their cost is excluded from reported agent elapsed time. Record them separately if measuring full
command startup. Synchronous analysis does add latency during agent execution: measure compute and
analysis write/flush intervals using a monotonic clock and retain per-call observations.

Report callback compute, flush, and the relation to runtime entry separately. A proposal-to-runtime gap may
also include other callbacks or framework work and is not itself a pure compute measurement. Keep cold
and cached comparisons interpretable; do not label a single run's elapsed time as controlled attribution
overhead. Final audits, report export, network latency, and quota waiting require their own timing scope.

There is **no hard deadline** in this version. Input-size limits are not a wall-clock timeout. The callback
is synchronous, so a slow callback delays the agent. Fail-open refers to handled tracer errors; it does not
provide a maximum wait guarantee for a stalled backend.

Runtime tracer errors must leave the primary agent request/action path intact. Persist sanitized error and
incompleteness information where possible, without substituting a fabricated score, analysis, or success
receipt. Primary recording failure must not feed an unpersisted event to the attribution subscriber. A
subscriber failure must not relabel a successfully recorded primary event as a missing observation.

An agent can succeed while attribution is incomplete. Preserve the native utility result and agent status,
set attribution completeness to false, and return CLI exit code **2** for this incomplete-attribution run.
An observed runtime entry without a matching analysis, a missing successful analysis flush, a recorder or
subscriber failure, or a failed sidecar write must not be hidden by an otherwise successful agent answer.
Semantic components' explicit unscored
states must remain visible rather than becoming negative matches or being silently omitted.

## Frozen validation matrix

Validation proceeds in this order. The fresh Groq trial is allowed only after the offline checks pass; this
ordering prevents spending an API run on known instrumentation faults. Keep all test and run artifacts.

| ID | Check | Acceptance evidence |
| --- | --- | --- |
| O1 | Detached, redacted callback input | Callback sees exactly the successfully flushed event snapshot; mutation and failure tests leave primary data unchanged |
| O2 | Source-prefix boundaries | Future results, invisible result metadata, and a same-response call's later result cannot enter a proposal's analysis |
| O3 | Multiple calls and errors | All proposal identities remain distinct; invalid/unknown tools, runtime exceptions, and multi-call responses preserve analysis and runtime links without inventing execution |
| O4 | Offline on/off invariance | Actual outbound request bodies, native history, and final simulated environment agree with online attribution off versus on |
| O5 | Failure isolation | Controlled compute, subscriber, write, and flush failures preserve primary behavior, expose incomplete attribution, and exercise CLI exit code 2 after agent success |
| O6 | Local semantic setup | The fixed MiniLM revision/file hashes load locally; invalid pins/options fail before a model request; enabled component metadata is recorded |
| O7 | Language and serialization | Generated HTML and decoded JSON/JSONL authored text are English; source IDs, codepoint spans, scores, and observed data are unchanged |
| L1 | One fresh clean live trial | Native `workspace/user_task_20`, current fixed Groq configuration, local pinned MiniLM, and online attribution enabled |
| L2 | Live execution order | Every proposed call has a successful flushed analysis, and every observed runtime entry occurs after its matching analysis flush |
| L3 | Live versus replay agreement | Replay the same saved events with identical component/model settings; corresponding call `fields` arrays are exactly equal |

For O4, use fixed responses and fresh simulated environments in both conditions. Include a multiple-call
response and tool-error cases. If tools embed wall-clock values, control that external clock equally in both
offline conditions and disclose it. Do not remove arbitrary payload/history/environment fields merely to
force equality. Instrumentation files, timings, run identifiers, and enabled-mode metadata are expected
differences; the actual request bodies and native task behavior are the comparison targets.

For L1, keep `configs/groq.toml` settings fixed: Groq `openai/gpt-oss-120b`, AgentDojo `v1.2.2`, temperature
0, low reasoning effort, 4,096 maximum completion tokens, eight tool rounds, 60-second request timeout,
and zero SDK retries. Override only the selected task and the stated attribution options. Record any
explicit pacing configuration in the execution record. Do not change the prompt, tools, or simulated
environment to improve the result. AgentDojo's existing no-final-text retry behavior is retained and must
remain visible as separate episodes; no additional trial is substituted to discard a failure.

Task 20 requests an availability check and an invitation to Sarah Baker. Its reference workflow provides
calendar and contact sources followed by event creation. That is expected coverage, not a requirement to
force the model to take exactly three calls. Preserve whatever calls, errors, retries, and native utility
result the fresh run actually produces. A clean execution milestone does not require declaring the model
successful when its native evaluation fails.

For L2, validate file records and monotonic times using explicit identities. Check all proposals, including
ones that never enter runtime. For calls that do enter runtime, require a matching earlier completed flush.
Report missing or unsuccessful analyses as incomplete; do not exclude them from the denominator. This
test establishes placement before the observed top-level runtime boundary, not a hard real-time guarantee.

For L3, run the existing offline `provenance` exporter against that fresh run with the same local model pin.
Hash its original `events.jsonl`, `manifest.json`, and `summary.json` before and after export. Match calls by
run, proposal, and request identity and compare the entire `fields` arrays, including candidate identities,
spans, statuses, scores, truncation, and component metadata. Compare observational timings separately; do
not normalize field differences away. Replay adds no Groq calls and does not read evaluation labels or
assistant development annotations as inputs.

Audit generated language with the existing report-language tool, and also inspect newly generated decoded
JSON metadata and JSONL strings. English presentation must not be achieved by silently translating raw
evidence, changing offsets, or hiding characters behind escapes. If a future live source intentionally uses
another language, retain it and disclose the original-evidence exception separately.

## What the results can establish

Passing this protocol would establish that source-candidate computation can run during an actual clean
agent execution, before the observed tool runtime, while preserving the tested primary behavior. It would
also establish agreement between live and replayed component outputs on the same observed inputs and
provide per-call timing measurements under the recorded local setup.

It would not establish source-attribution accuracy, malicious propagation, authorization correctness,
causal influence, attack resistance, cross-session memory handling, or the cost of the paper's complete
method. One task is an integration check, not an independent benchmark or evidence of generalization.
Exact or semantic matches remain candidate evidence; high similarity is not a probability of provenance.

## Remaining paper components

The project still needs the separately specified source/sink policies, ordered cascade and its budget
accounting, DCPG lineage and memory restoration, a distinct canary condition, and sink-driven controlled
counterfactual analysis. Passive primary runs and any later intervention conditions must have separate
configurations and artifacts. This milestone implements none of those interventions implicitly.

After those method components are defined, evaluate on a frozen set with independent source judgments,
clean and attack conditions, repeated trials, ablations, source ambiguity/unknown analysis, and measured
costs. The existing eight assistant development drafts are non-blind and non-independent; they cannot
supply independent accuracy labels. Keep the paper-based baseline separate from proposed changes and
disclose unresolved paper details as local implementation choices. See [REPRODUCTION.md](REPRODUCTION.md).
