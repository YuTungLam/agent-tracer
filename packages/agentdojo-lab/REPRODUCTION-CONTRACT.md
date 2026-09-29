# Fixed NeuroTaint completion contract

## Material Passport

- Origin Skill: academic-research-suite
- Origin Mode: paper-to-implementation audit and integration
- Origin Date: 2026-09-10
- Verification Status: M1–M7 IMPLEMENTED; retained and live runtime integrations verified
- Version Label: paper-conformance-contract-v1

## The target and the stopping rule

The user clarified the target on 2026-09-10: independently implement NeuroTaint's
published method ideas in the existing AgentDojo laboratory, then use controlled
experiments to investigate reproducible limitations. Matching the authors' code,
original datasets, framework inventory or numerical tables is outside this task.
Missing author artifacts do not block it. The method reference remains
[arXiv v1, Sections 4.1–4.4](https://arxiv.org/html/2604.23374v1#S4).
Paper details that admit multiple implementations require disclosed choices;
they do not justify leaving the corresponding operation unimplemented.

Three outcomes must stay separate:

1. **Method implementation complete within the declared adapter and choices.**
   Every required operation exists, connects to the intended agent runtime and
   passes conformance checks. The completed-trace composer and online causal
   integration are implemented and verified. Incorrect detector predictions do
   not make the code absent, while untriggered live branches remain coverage limits.
2. **Evaluation completed, with supported and unsupported claims recorded.**
   Every frozen trial is accounted for. An unexercised branch is a coverage result;
   an unsuccessful trial is retained. Finishing does not require favorable metrics.
3. **Optional original-results replication, outside the current task.**
   The original scenario definitions, models, labels, aggregation, baselines and
   measurement scopes must be matched closely enough to support that claim.

Neither an independent human labeling campaign nor proof of hidden model reliance
is a prerequisite for outcome 1. A fresh agent replay is stronger validation of
auditor predictions, not an additional requirement of our declared judge-based
interpretation. The paper also describes re-querying the agent; the precise
executable distinction is unresolved in the inspected text. Likewise, an actual live first hit at every tier is not
required to establish that those functions and branches exist. Such observations
are necessary only for the corresponding live-performance claims.

Do not rename a sequence of small pilot closeouts as full-paper progress. Do not
increase the requirements after a successful check without explicitly changing
this contract. Historical progress files describe their own frozen phases.

## Method checklist

The rows below are functional requirements, not equally weighted percentages.
The previous audit completed M5 and verified M6 on three retained traces. M7 now
connects that composition to the native runtime boundary and records its outputs
before tool execution. The seven requirements are implemented under the declared
adapter. Completion does not require running new attacks until one succeeds, and an
unreached live judge branch remains a coverage result rather than absent code.

| ID | Requirement and completion criterion | Existing implementation | Audit disposition |
| --- | --- | --- | --- |
| M1 | Explicitly declared source/sink policy; bind each comparison to the actual earlier model-visible source and sink argument. Unknown tools and absent sources remain distinguishable. | `policy.py`, `recording.py`, `provenance.py`, `online.py`; policy and prefix-isolation tests. | Implemented and tested for AgentDojo. |
| M2 | Registered Canary, exact LCS, pinned embedding similarity, chunk coverage and ordered per-source routing; positive, negative, boundary, failure and truncation behavior. | `canary.py`, `lexical.py`, `semantic.py`, `cascade.py`; native scripted routing tests and real local encoder measurements. | Implemented with disclosed local choices. |
| M3 | Preserve graph paths and content-bound lineage through real storage and a fresh session; retrieval restores ancestry without itself declaring a sink flow. | `lineage.py`; native file adapter, checkpoint and memory tests, real cross-session copy pilot. | Implemented for the file adapter. General backend portability is outside this adapter claim. |
| M4 | Eligible sinks invoke single-source planning plus an isolated judge; represent two-source cases using an explicitly declared joint-probe rule; preserve confidence and incomplete results. | `causal_v2.py`, `causal_v2_audit.py`; single/pair binding, missing evidence and request-budget tests. | Implemented under the declared judge interpretation; the two-source decision rule is a local completion of an underspecified detail. |
| M5 | One entry point joins trace verification, explicit evidence, optional causal auditing, all-sink decisions and a derived provenance graph. Joint-removal evidence must not masquerade as two independent causes. | New `paper_audit.py`; original DCPG/checkpoints remain unchanged. | Integrated; exact source/probe/response bindings tested. |
| M6 | Verify M5 on retained explicit, implicit and restored-memory evidence; invalid/missing judgments and unselected sinks remain accounted for; outputs and source hashes verify. | Fresh integration receipts and regression tests, with zero new primary trajectories. | Three retained-trace integrations pass; controlled negative, unknown and joint cases covered by tests. |
| M7 | Trigger isolated causal auditing at eligible runtime sinks using bounded requests and prefix-only context; record typed graph updates, timing, overhead and unknown/error outcomes without changing agent actions or model weights. | `online_causal.py`, `online.py`, `runner.py`, `verify_online_causal.py`, interactive report and native-equivalence tests. | Implemented. A clean live run verified native integration and two pre-runtime receipts; its Tier-2 positive made the causal fallback ineligible, so live judge-request coverage remains unobserved. |

The four fixed local profiles already exist in `profiles.py`. Implicit-string and
safe-control selection is caller-declared; restored-memory routing uses bound
ancestry. This audit does not invent an automatic classifier as an extra paper
requirement. The passive online observer remains available. The same proposal
composer is shared by the completed-trace audit and the opt-in synchronous M7 sidecar.

## Runnable completion and verified examples

Open [the compact completion report](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260910-paper-conformance-v1/index.html).
The three final compositions are
[explicit](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260910-paper-conformance-v1/explicit-v2/index.html),
[control](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260910-paper-conformance-v1/control-v2/index.html), and
[memory](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260910-paper-conformance-v1/memory-v2/index.html).

```bash
.venv/bin/python -m agentdojo_lab.paper_audit \
  --run runs/20260910-semantic-native-live-v1/runs/paraphrase-r01 \
  --output reports/NEW-completed-audit
```

The default makes no new API requests. `--auditor EXISTING_EXPORT` reuses and
revalidates recorded replies; `--live --max-requests N` explicitly enables the
existing no-tools transport with a finite budget. Primary agents and tools are
never rerun by this command. A pending judge remains unknown in the default mode.

Run the online form on a fresh output path, then verify every binding, budget,
timing relation and derived edge without changing the source run:

```bash
.venv/bin/dojo-lab run \
  --config configs/groq_online_causal.toml \
  --output runs/NEW-online-causal

.venv/bin/python scripts/verify_online_causal.py \
  --run runs/NEW-online-causal \
  --output reports/NEW-online-causal-verification.json
```

The retained clean run is
[20260910-online-causal-live-v1](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/runs/20260910-online-causal-live-v1/report.html).
It completed the native task with two proposals and two matching causal receipts
before runtime. The first proposal was not a sink; the only selected sink had six
Tier-2 hits and skipped all causal probes under the implemented routing rule. This
run therefore does not claim eligible-judge behavior or judge accuracy.

The initial integration attempt passed the explicit case and exposed two local
compatibility defects. Old auditor plans used a smaller frozen source/pair budget;
the composer now preserves it and checks an exact recomputation. Old memory files
lacked canonical condition fields; a narrow verified adapter now permits their
explicit analysis while leaving causal transport unavailable. Newly recorded
memory runs include the required passive condition, verified through the standard
planner. The initial outputs and executed composer are retained separately.

The final three compositions account for seven proposals and three selected sinks:
two explicit-positive decisions and one predicted-control-positive decision.
The memory decision includes the original session's multi-edge source path.
Three existing auditor replies are reused; there are zero new generative requests
or native tool executions. These are integration examples, not an accuracy sample.

The current regression suite passes 1,848 tests; Ruff and `git diff --check` pass.
M7 native-equivalence tests preserve primary requests, messages, executed calls,
environment state, usage and errors with the sidecar enabled. The read-only live
verifier passes all thirteen checks. The language audit finds no Chinese in 257
HTML and 525 JSONL files. Automated tests cover the causal-view timeline and diagram
links; separate browser visual QA is not claimed. See [M7-RESULTS.md](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/M7-RESULTS.md)
and the earlier [completed-trace verification receipt](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260910-paper-conformance-v1/validation-final.json).

## Evidence coverage, not absent code

The runtime inventory is in
[`runtime-coverage.json`](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260910-paper-conformance-v1/runtime-coverage.json).
Its conclusions are bounded to the inspected files, not all possible runs:

- Registered Canary comparisons exist in real traces, but no real Tier1 hit was
  found. The passive memory pilot's task-data marker is not a registered Canary.
- Recorded real-agent ordered hits stop at Tier2. Direct semantic measurements,
  native scripted semantic routes and real-encoder offline entry already exist.
- The real cross-session file pilot demonstrates exact-copy ancestry, not
  transformed semantic memory attribution.
- The latest four rewrite processes omit the requested background read. This is
  source-availability and task-compliance evidence, not four true negatives.
- Real implicit-string and safe-control profile runs were not located. Their
  configuration and routing are exercised by deterministic tests.

These facts limit which experimental claims can be made. They must not silently
reopen a completed implementation gate or be promoted to a method failure.

## Paper detail and artifact limitations

Section 4 leaves LCS sequence units/preprocessing, chunk size/overlap, the precise
coverage denominator, full neutralization prompts and a joint-cause decision rule
insufficiently specified for a unique implementation. Its per-source probe rule
also needs reconciliation with the stated per-sink call cost. Our choices remain
explicit assumptions, not author-confirmed settings.

The following original-results requirements are archival context, not completion
gates for the current task. For original results, Section 5 uses TaintBench's 400 scenarios, 20 frameworks,
`gpt-4.1-mini`, five repetitions and majority aggregation. Groq
`openai/gpt-oss-120b` in AgentDojo is a different setting.

The public-artifact search is recorded in
[`public-artifacts.json`](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260910-paper-conformance-v1/public-artifacts.json).
An unlocated download or failed repository query means unavailable/unverified in
that search, not proof that no release exists. Original result replication also
requires the actual scenario and label manifest, framework versions, full run
configuration, FIDES adaptation, stage-group scoring, threshold-sweep and cost
recipes. Stage-group recall is not automatically a component-removal ablation.
We must not invent the missing experimental recipes.

## How a result can support a research gap

Use four separate classifications:

| Classification | Example in this project | Required response |
| --- | --- | --- |
| Our engineering defect | Missing composed audit, parser rejecting English punctuation, wrong output accounting. | Fix and verify the implementation; retain failed records. |
| Setting or execution restriction | Agent skipped a source, provider failure, blocked execution, missing original model/data access. | Record the limit. It is not evidence against NeuroTaint. |
| Reproducibility ambiguity | Multiple plausible chunking or sequence-unit interpretations. | Freeze reasonable alternatives and compare their consequences before blaming the method. |
| Candidate method limitation | Known-origin controls still match an unused source; a bound judge prediction disagrees with an observed replay. | Reproduce under a declared implementation, exclude coding/setting explanations, evaluate on fresh cases and compare relevant prior methods. |

An implementation that we have not finished is not the paper's research gap.
An implementation consistent with the disclosed components and declared choices
that produces a reproducible counterexample can support a bounded limitation
claim. Novelty additionally requires checking whether prior
work already identifies or addresses that limitation. Existing controlled findings
are starting points; they do not yet establish a new general solution.

No human relabeling is assigned by this contract. Program-defined controls can
test known construction relations. Claims about natural real-agent attribution
accuracy require additional reference evidence and must retain unknowns.

## Runtime boundary

The original conversation record at 2026-09-09T23:16:27.446Z reports an errored
Codex subagent with the message "This content was flagged for possible cybersecurity
risk" and an OpenAI Trusted Access reference. This is a Codex/OpenAI-side rejection,
not a recorded Groq HTTP/API rejection or an experimental agent refusal. The exact
internal classifier is not established by that message. That specific execution
was not retried or disguised. The completed conformance audit and the
new integration use existing artifacts and offline tests. They do not remove that
execution restriction or turn normal-task observations into malicious evidence.

Model weights, CTTA, action blocking and a new defense remain outside this baseline.
Future extensions must preserve a runnable frozen baseline and use separate names.
