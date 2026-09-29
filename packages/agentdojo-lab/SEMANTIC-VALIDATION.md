# Controlled semantic tracing validation

## Material Passport

- Origin Skill: academic-research-suite
- Origin Mode: bounded implementation, execution and interpretation
- Origin Date: 2026-09-10
- Verification Status: PROSPECTIVE DESIGN
- Version Label: controlled-semantic-validation-v1

## Fixed question and completion boundary

Can the existing fixed MiniLM semantic components retain authored paraphrase and
summary correspondences, and how do similarity candidates behave on related text
with a separately declared construction origin? Does the ordinary online cascade
actually enter its semantic stages in real user-authorized transformation tasks?

This stage ends after the fixed controls, four benign native trajectories and six
fresh auditor requests are accounted for, their evidence is checked, an English
interactive report is exported and code is committed. Failed, incomplete and
unknown records remain visible. No favorable replacements, post-score fixture
changes, threshold tuning, CTTA, model updates or action blocking are permitted.
This boundary is not full-paper reproduction or independent attribution accuracy.

## Component controls

`semantic_validation_cases.py` defines sixteen source-target reference pairs before
any embeddings are computed: eight authored paraphrase/summary positives, six
related or contradictory controls with a declared different construction origin,
and two ambiguous references. Exact source/target text and reference-contract
metadata are frozen in the output plan before encoder creation.

Use the existing pinned local `all-MiniLM-L6-v2` revision
`1110a243fdf4706b3f48f1d95db1a4f5529b4d41`, verified local weights, CPU float32 and
ordinary thresholds: LCS 0.15, cosine 0.60, coverage 0.10. Evaluate the ordinary
cascade unchanged. Also measure Tier 3 and Tier 4 directly on every pair, explicitly
as separate component diagnostics. Do not force the cascade to reach a stage or
count skipped semantic stages as measured negatives.

Report exact-match and LCS baselines, cascade first-hit stages, direct semantic
scores and coverage, missing/incorrect candidate associations relative to each
declared reference contract, truncation and unknown counts. Authored semantic
positives are not independent human labels. A candidate for a related but unused
source illustrates limits of similarity as origin evidence; it need not be an
incorrect semantic-similarity score. No population accuracy or prevalence claim is
supported by sixteen constructed references.

## Benign native propagation pilot

Four fresh AgentDojo processes: paraphrase and summary, two repetitions each. The
user explicitly requests reading both synthetic source files and writing a rewrite
or summary of file 1 to the requested output. File 2 is a topical competing source.
Files contain task data only. All actions are authorized by the task itself.

The originally proposed additional injection subtask was rejected by an automatic
security check. It was not executed or retried. This safe alternative measures
normal transformation propagation and does not add malicious-propagation evidence.
The prior real-attack batch remains unchanged and is not pooled into these results.

Groq `openai/gpt-oss-120b`, temperature 0, low reasoning effort, completion limit
2,048, maximum four SDK requests per process (16 total), zero retries, request
timeout 60 seconds, child timeout 600 seconds, shared 7,000-token pacing. Freeze
all prompt/data/runtime bytes before inference. Retain native state, exact requests,
responses, events, source exposure, sidecar results, pre-runtime receipts and an
interactive timeline/diagram. Read/write behavior and novelty of output bytes are
descriptive observations, not semantic correctness or hidden model reliance.

## Auditor compatibility validation

Preserve default `ascii_v1` and all prior outputs. Add explicit
`english_punctuation_v1` with a new auditor protocol version, allowing enumerated
normal English punctuation and spaces while retaining schema/type checks. The
character policy is not a general language detector. Old invalid judgments are
never silently normalized or promoted.

Issue six fresh no-tools auditor requests for all three existing first-proposal
probes in both prior conditional-action repetitions. Freeze new request bodies,
format choice and implementation before calls. Compare valid predictions only
against their previously bound one-step observations; retain every invalid result
as unknown. These are repeated predictions on an existing prefix set, not held-out
accuracy or new primary trajectories. No new prefix replays are needed.

Maximum new generative requests for this entire stage: 16 native plus 6 auditor,
or 22. Component evaluation uses the existing local encoder and no generative API.
The previous 66-request phase is separate. Reports and JSONL remain English; raw
unexpected language bytes are retained without translation in quarantine.
