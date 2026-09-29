# Paper-based NeuroTaint reproduction

## Material Passport

- Origin Skill: academic-research-suite
- Origin Mode: implementation and experiment planning
- Origin Date: 2026-09-08
- Verification Status: bounded phase closed with evidence limits; independent attribution acceptance unmet
- Version Label: paper-based-reproduction-v1

## Objective

Final disposition (2026-09-09): [CLOSEOUT.md](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/CLOSEOUT.md) and the
[English evidence ledger](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260909-reproduction-closeout-v1/index.html) close the bounded
AgentDojo adaptation. Seven local engineering gates are accepted; gate8 is not accepted.
No further experiment is scheduled. This is not complete paper-method or original-result equivalence.

Independently implement NeuroTaint from the published method and test whether it works in the AgentDojo
setting. Access to author code is not a prerequisite. Matching the original tables numerically is not the
acceptance condition. The paper remains the method reference; original code or artifacts may provide
additional checks if they become available.

Implement specified components faithfully. Where the paper is incomplete, freeze and disclose the local
choice before interpreting results. Keep separate names and configurations for the paper-based baseline
and proposed modifications. Do not tune thresholds using evaluation labels or describe an engineering
assumption as an author-specified choice.

## Implementation sequence

1. Completed: recorded request prefixes, exact baseline, Tier 2 LCS, local MiniLM Tier 3, and a disclosed
   Tier 4 chunk/coverage implementation. The original independent mode remains available.
2. Completed for the tested integration scope: opt-in live attribution writes a separate JSONL sidecar and
   flush receipts before tool runtime entry. Deterministic native controls preserve requests/actions/history/
   environment. One fresh Groq task has 3/3 pre-runtime analyses, 7 fields and 36 semantic comparisons,
   with exact live/replay agreement. See [ONLINE-RESULTS.md](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/ONLINE-RESULTS.md).
3. Completed for the ordinary passive condition: frozen workspace source/sink policy and ordered active
   Tier 2–4 routing. Ten saved runs and a fresh Groq task pass replay checks, with actual encoder-boundary
   controls. Tier 1 is explicitly disabled. See [CASCADE-RESULTS.md](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/CASCADE-RESULTS.md).
4. Completed for the bounded file adapter: candidate DCPG, private persistence, and actual two-session
   native memory restoration. Ten saved traces repeat exactly; the selected fresh Groq task failed at
   provider validation after search/create, while its two executed proposals and final graph verify.
   See [LINEAGE-RESULTS.md](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/LINEAGE-RESULTS.md). This is engineering acceptance, not task efficacy.
5. Completed for the declared engineering scope: a separate UUID Canary condition, native positive/negative
   controls and cross-session restoration. The real pair confirms marker insertion/exposure but both trials
   fail before a sink; real sink survival remains unknown. See [CANARY-RESULTS.md](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/CANARY-RESULTS.md).
6. Completed for the bounded analyzer scope: source neutralization over exact proposal prefixes and a
   separate no-tools A/B auditor, following the paper's displayed judge prompt. Seven native controls
   preserve primary behavior; two preselected Groq auditor calls return valid judgments. These are
   predictions, not observed counterfactual agent behavior. See [COUNTERFACTUAL-RESULTS.md](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/COUNTERFACTUAL-RESULTS.md).
7. Completed descriptive evaluation and closeout: three separately frozen ten-slot native batches,
   explicit failure/exposure accounting, captured-prefix exact/LCS comparisons, assisted development
   review and optional decoded-scalar diagnostics. Independent source judgments, second review/
   adjudication and scoring were not completed; gate8 is therefore not accepted.
   See [CLOSEOUT.md](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/CLOSEOUT.md) and [EVALUATION.md](EVALUATION.md).

No CTTA, model-weight updates, automatic action blocking, or real-account operations are part of this scope.

## Acceptance progress

[REPRODUCTION_PROGRESS.json](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/REPRODUCTION_PROGRESS.json) fixes eight equal acceptance gates. Seven are
accepted as of 2026-09-09: local components, deterministic live integration, fresh real-agent timing
validation, source/sink policy with the ordinary passive cascade, DCPG with native memory restoration,
the separate Canary intervention condition, and the isolated counterfactual auditor. The remaining
gate is independent clean/injected evaluation, recorded as not accepted at bounded closeout. This count is not a work estimate,
accuracy measurement, or claim that the original paper's tables have been reproduced. Completing an
independent evaluation can include negative results; benchmark efficacy remains a separate measurement.

## How a reproduction failure becomes a research question

A failure is evidence to investigate, not automatically a research gap. Preserve the exact inputs,
configuration, source/argument identities, outputs, and repeat results. Then distinguish:

- Implementation errors, including serialization, tokenization, time boundaries, and missing instrumentation.
- Underspecified choices and sensitivity to reasonable alternate chunking, thresholds, and neutralization.
- Setting differences, including model, tool format, task distribution, and source availability.
- Method limitations that persist after the above checks, such as topical overlap, competing sources,
  short identifiers, transformed facts, or decision changes without copied content.

Develop a gap claim only when controlled examples and evaluation support the limitation. Keep unsuccessful
runs and negative findings. Neither similarity nor a judge confidence score constitutes causal ground truth.

## Language convention

Generated HTML interfaces, diagrams, report explanations, JSONL annotations, and assistant-authored notes
are in English. Conversation with the user may remain Chinese. Future descriptive task metadata is English.

Existing observed event/native records already contain no Chinese text. The language migration changes
presentation text and assistant annotation notes, preserving event contents, source IDs, offsets, scores,
measurements, and frozen experiment hashes. Legacy Chinese task descriptions receive an explicitly labelled
English rendering in derived pilot pages; the frozen source configuration is unchanged.

Audit all generated HTML and decoded JSONL keys/string values with:

```bash
.venv/bin/python scripts/audit_report_language.py
```

The audit detects Chinese text after JSON decoding and in HTML entities/Unicode escapes; encoding text
with escapes is not a translation. Raw evidence must not be silently translated or rewritten. If future
experiments intentionally introduce non-English source data, retain the observation and distinguish an
English presentation from original evidence explicitly.
