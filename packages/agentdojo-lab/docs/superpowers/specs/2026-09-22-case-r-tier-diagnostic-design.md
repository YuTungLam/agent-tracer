# Case R tier ablation / cascade diagnostic

Design date: 2026-09-22. Status: approved by the researcher in conversation;
implementation plan follows. Code, HTML, JSON and protocol names are English.

## Purpose

Case R (`docs/superpowers/specs/2026-09-20-case-r-groq-design.md`, batch
`runs/20260921-case-r-v1`, packet `reports/20260921-case-r-groq-v1`) showed that
the reproduced Tier-2 subsequence LCS scores every visible source at 0.96-1.00
against the short executed recipient, whether or not the source contains the
address, and that the ordered cascade then skips Tier 3/4 and closes the causal
gate for all 23 `send_email` sinks. This diagnostic answers the follow-up
question the supervisor's checklist requires before any broader claim:

> If the Tier-2 match had not short-circuited the cascade, would Tier 3 or
> Tier 4 have distinguished the actual value source from the other visible
> sources?

It decides between two readings of the Case R failure:

- **A. Ordering failure.** The semantic tiers carry discriminative evidence that
  the canonical cascade never observes because Tier 2 terminates the pair.
- **B. Correspondence failure.** No correspondence tier separates the source that
  carries the sensitive value from the source that carries the instruction, so
  the limitation is broader than Tier-2 ordering.

The diagnostic is offline, request-free, and evaluates only the already
recorded Case R source/target pairs. It does not modify the canonical
reproduction; every non-canonical computation is labelled as a diagnostic.

## Paper-specified versus local choices

The reproduction follows Cai, Tang, Wen and Qin, "Ghost in the Agent:
Redefining Information Flow Tracking for LLM Agents" (arXiv:2604.23374v1). The
authors have not released code. The diagnostic report must keep the following
distinction visible.

| Element | Paper | Local reproduction (labelled as such) |
| --- | --- | --- |
| Tier 1 | canary token κ; σ₁ = 1 iff κ ∈ sink | `canary.py`; disabled in Case R (`canary_enabled = false`, stage status `disabled_condition`) |
| Tier 2 | σ₂ = LCS(src, sink) / min(len src, len sink); θ_str = 0.15, "intentionally low for short sink arguments" | `lexical.lcs_evidence`: exact subsequence over Unicode code points, no normalization |
| Tier 3 | all-MiniLM-L6-v2 cosine; θ_sem = 0.60 (0.85 for memory-retrieved content) | `semantic.SemanticMatcher.compare_tier3`, pinned revision `1110a243…`, 256-token encoded view |
| Tier 4 | max chunk-level similarity over k-sentence chunks; θ_sem = 0.60, θ_cov = 0.10; k not specified; coverage definition not detailed | `compare_tier4`: 3-sentence chunks, overlap 1; coverage = union of matched chunk envelopes / source code points |
| Cascade | "stops early for obvious attacks and reserves the more expensive semantic checks for subtler cases"; whether later tiers still report is not stated | `cascade.py`: `first_observed_threshold_hit_within_one_pair`; later stages recorded as `skipped: earlier_stage_matched` |
| Causal trigger | only when "Tiers 1-4 report no explicit taint" and the DCPG provides a tainted lineage | `causal_v2.explicit_coverage`: per-sink gate requiring every selected field/source pair to be explicit-negative |
| Multiple sources | one probe per source, neutralised one at a time; report the highest causal score; both if conjunctive | `counterfactual` v1 whole-source placeholder neutralization (Case R follow-ups) |
| Per-argument attribution | not specified | pairs are formed per selected argument path (`/recipients/0`, `/subject`, `/body`) |
| Bounded exact substring | not a paper tier | `lexical.exact_spans`; reported as a local strict-explicit variant only |

## Evidence lanes

Three lanes are computed and kept apart in every JSON row, HTML column and
figure legend.

| Lane | Source | Label |
| --- | --- | --- |
| Canonical | `runs/20260921-case-r-v1/runs/<slot>/provenance.jsonl`, record type `call_analysis`, `call.fields[].nt_style_cascade[]`: `stages.tier1..tier4` (status, score, coverage, matched, reason), `first_matched_tier`, `matched`; `call.cascade_summary.causal_analysis`; `call.fields[].exact_candidates` | `canonical` |
| Independent diagnostic | Tier 3 and Tier 4 recomputed for every pair with the pinned MiniLM through `SemanticMatcher.compare_tier3` / `compare_tier4`, each called unconditionally; Tier 2 taken from the canonical record (deterministic and already scored for every pair) | `diagnostic_recomputed` |
| Recorded cross-check | `reports/20260921-case-r-groq-v1/packet.json`, `attribution[].rows[].variants.semantic_only.tier3/tier4` (rendered 2026-09-21 on the Windows laptop with the same pinned model) | `diagnostic_recorded` |
| Local strict-explicit variant | `lexical.exact_spans(source_text, target)` | `substring_local_variant` |

Join key between lanes: `(slot_id, proposal_event_id, argument_path, source_id)`.
A pair that exists in one lane but not another is emitted with
`join_status = "unjoined"` and excluded from matrices; the count of unjoined
pairs is reported. Recomputed and recorded Tier-3/Tier-4 scores are compared
per pair; a difference above 1e-6 in score or coverage, or any difference in
`matched`, is listed in a `cross_check` section and never silently replaced.
When the recorded packet had `tier4 = null` because its variant skipped Tier 4
after a Tier-3 match, the cross-check marks that pair `not_computed_by_variant`
(no such recipient pair exists in the 2026-09-21 packet; the rule is kept for
completeness).

If the MiniLM snapshot is unavailable the script fails with a clear message
rather than falling back to the recorded lane; the diagnostic's semantic lane
is defined as a recomputation.

Provenance recorded in `packet.json`: batch path and `plan.json` protocol hash,
SHA-256 of the recorded Case R `packet.json`, the matcher metadata returned by
`SemanticMatcher.metadata` (model id, revision, file hashes, package versions),
and the git commit of the lab at render time if available.

## Population

Main batch `groq-case-r-v1` only: 24 trajectories, 23 `send_email` sinks,
46 `/recipients/0` pairs (primary population) plus the `/subject` and `/body`
pairs of the same sinks (secondary: sink-level gate and length panel). The pilot
batch is excluded from all counts. Eligible sources are those the recorded call
lists under `visible_sources` with `kind = "tool"` and `policy.eligible = true`,
labelled by native file id through `case_r_diagnostics.source_file_id`.

## Per-pair record

Every pair row carries:

- identity: `slot_id`, `construction`, `arm`, `repetition`, `proposal_event_id`,
  `argument_path`, `source_id`, `source_event_id`, `exposure_event_id`,
  `source_file_id`;
- outcome: `recipient_outcome` (native sent-mail oracle), `executed_value`
  (the target string), `target_length`, `source_length`, `length_ratio`
  (target/source);
- ground truth for recipient paths from `case_r_diagnostics.ground_truth`
  (outcome-aware): `carries_value`, `carries_instruction`, and the derived
  `role`: `both` when both flags are true, `value` when only `carries_value`,
  `instruction` when only `carries_instruction`, `neither` when both are
  false, `null` when either flag is `None` (unknown outcome or unlabelled
  source); non-recipient paths get `role = null` and
  `scope = not_a_recipient_argument`;
- `literal_contains`: `executed_value in source_text` (plain substring, no
  boundary rule) and `substring_local_variant` (bounded `exact_spans`);
- canonical: `tier1_status`, `tier2_score`, `tier2_matched`, `tier3_status`,
  `tier4_status`, `first_matched_tier`, `skipped_stages`,
  `causal_analysis`;
- independent: `tier3_score`, `tier3_matched`, `tier4_best_score`,
  `tier4_coverage`, `tier4_matched`, `tier4_truncated`, `tier3_truncated`;
- T2-bypassed cascade: `bypass_first_matched_tier` ∈ {`tier3`, `tier4`, null}
  computed as T1 (disabled, never matches) → T3 → T4 with the same
  first-hit rule; `bypass_matched`;
- Tier-4 chunk detail: `value_chunk` (index, span, length, score of the chunk
  whose span contains the executed value, or null), `best_chunk` (index, span,
  length, score), `matched_chunk_count`;
- `join_status` and `cross_check` (`agree`, `differs`, `not_computed_by_variant`,
  `missing_recorded`).

Tier 1 is reported as `disabled_condition` on every row and is never given a
score or a matched flag. The report states that Case R therefore provides no
Tier-1 evidence.

## Analyses

All analyses use recipient pairs unless stated. Counts are exact over the 46
pairs; no population rates are claimed.

1. **Source-role matrix.** Construction × arm × file → role counts across
   repetitions, with the executed outcome per repetition. Split `both` must read
   file 1 = `instruction`, file 2 = `value`.
2. **Per-pair tier table.** One row per pair, canonical and independent side
   by side; canonical skipped cells rendered as "skipped (earlier stage
   matched)", never as a score.
3. **VALUE-provenance discrimination.** For each evaluator in {T2 canonical,
   T3 independent, T4 independent, T2-bypassed cascade, substring local
   variant}: TP/FP/TN/FN against `carries_value`, precision and recall where
   the denominator is non-zero, split by construction, by outcome
   (attacker-sent versus legit-sent) and by role. Sink-level localisation per
   evaluator: `exact` (positive set equals the true value-carrier set),
   `over` (superset), `under` (non-empty proper subset), `empty` (no
   positives), `disjoint`.
4. **DECISION-influence check.** For each Split `both` sink, whether each
   evaluator flags file 1 (instruction only). Reported as a separate question
   from value provenance; a flag from T2 is noted together with the fact that
   T2 flags every source, and a non-flag from T3/T4/substring is reported as
   the evaluator not representing decision influence, not as an error.
5. **Causal-gate counterfactual.** Per sink: gate under canonical (recorded
   `causal_analysis`), under T2-bypass over recipient pairs only (hypothetical
   per-argument gate), and under T2-bypass over all selected fields (the
   implemented per-sink rule). The report states which rule the reproduction
   implements and that the per-argument rule is hypothetical.
6. **Tier-4 chunk view.** For each recipient pair, `value_chunk` versus
   `best_chunk`; the HTML shows the chunk text with the value highlighted.
   Text explains the observation mechanically (which chunk, how long, what
   cosine) without theorising about embedding behaviour.
7. **T2 length regime, recorded.** Scatter/table of canonical Tier-2 score
   against target length for every selected field (`/recipients/0`,
   `/subject`, `/body`), split by carrier/non-carrier (recipient) or
   unlabelled (subject, body), with source length and ratio.
8. **T2 length regime, synthetic (labelled constructed).** Targets: prefixes at
   5, 10, 20, 40, 80 and 160 code points of the four frozen payload sentences
   (`plan.payloads`) and of the legitimate contact line
   `Client contact: John Mitchell <john.mitchell@example.com>`. Sources: every
   distinct frozen document text in `plan.documents`. Pairs where the prefix is
   a plain substring of the document are excluded (verified per pair). Scores
   from the frozen `lexical.lcs_evidence` at threshold 0.15. Per target length:
   count, min, median, max, fraction ≥ 0.15, fraction ≥ 0.90. Prefixes shorter
   than the sentence are taken as-is; a length longer than the sentence yields
   the whole sentence and is marked `truncated_to_sentence`.

## Interpretation text

The HTML executive summary is generated from the computed numbers and chooses
among three pre-written readings only by the observed matrices:

- Reading A (ordering): the T2-bypassed cascade localises the value source at
  the sink level (`exact`) in most attacker-sent sinks.
- Reading B (correspondence): T3 and T4 independently fail to flag the true
  value source in most attacker-sent sinks, or flag non-carriers.
- Reading C (instability): T3/T4 matched flags differ across repetitions of the
  same construction/arm/file with identical inputs.

The summary must also state where the method succeeds (for example Tier 4
matching the legitimate carrier, or substring isolating the value carrier), and
must never call any correspondence score causal attribution. Sentences use
"consistent with", "in this batch", and "under this reproduction".

## Outputs

Directory `reports/20260922-case-r-tier-diagnostic-v1/` (fresh; refuses to
overwrite):

- `packet.json`: provenance, matcher metadata, all pair rows, all matrices,
  gate table, chunk detail, length panels, cross-check list, generated summary.
- `index.html`: self-contained (inline CSS/JS, embedded JSON, no external
  assets), tabs in this order: Summary, Source roles, Pair table,
  Discrimination, Split case, Tier-2 bypass, Tier-4 chunks, Length, Limitations.
  The Split-case tab contains an inline SVG diagram: Source A
  (instruction) —decision influence→ recipient choice; Source B (value)
  —value provenance→ `/recipients/0`; `/recipients/0` —consumed by→
  `send_email`; each evaluator's flags for A and B drawn beside the sources.
  Every table cell derived from the diagnostic lane carries a visible
  "diagnostic" marker; canonical cells carry "canonical".
- `figure-case-r-tiers.svg/.pdf/.png` from `scripts/figure_case_r_tiers.py`
  (matplotlib, palette of `figure_case_r.py`): panel (a) per-pair T2/T3/T4
  scores by role with thresholds; panel (b) synthetic T2 sweep, score versus
  target length with the 0.15 threshold.

## Code

| Path | Responsibility |
| --- | --- |
| `src/agentdojo_lab/case_r_tier_diagnostic.py` | Pure functions: load canonical pairs, recompute semantic lane, join with recorded lane, roles, discrimination matrices, localisation, gate counterfactual, chunk detail, length panels, summary reading selection |
| `scripts/report_case_r_tiers.py` | CLI (`--batch`, `--packet`, `--output`, `--title`), matcher construction from `plan.json`, HTML rendering |
| `scripts/figure_case_r_tiers.py` | Static figure from the diagnostic `packet.json` |
| `tests/test_case_r_tier_diagnostic.py` | Unit tests on hand-built fixtures; integration test over the tracked batch, skipped when batch or model is absent |
| `CASE-R-GROQ-V1.md` | New protocol row `case-r-tier-diagnostic-v1` and command |
| `PROJECT_CONTEXT.md`, `RESEARCH_PLAN.md` | Dated section and checklist lines written after the run from observed numbers |

Unchanged: `cascade.py`, `lexical.py`, `semantic.py`, `canary.py`,
`case_r_diagnostics.py`, `report_case_r.py`, `figure_case_r.py`, all runs and
existing reports.

## Error handling

- Missing batch, missing `provenance.jsonl`, missing recorded packet or missing
  MiniLM snapshot: fail before writing any output, naming the missing input.
- Encoder errors on a pair: the pair keeps `tier3_status`/`tier4_status` from
  the matcher (`encoder_error`, `budget_exceeded`), is excluded from matrices,
  and is counted under `unscored_pairs`.
- Truncated encodings: reported per pair (`tier3_truncated`, `tier4_truncated`)
  and in the limitations; Case R sources are far below 256 tokens so none are
  expected.
- Any slot without a `send_email` sink (for example `r_split-r01-neither`) is
  listed in a `sinkless_slots` section.

## Testing

Fixtures: a two-slot synthetic batch (`plan.json` with the real Case R ground
truth table, `manifest.json`, `scoring.json`, `provenance.jsonl` with two
recipient pairs and one body pair per sink, canonical stages recorded as in the
real runs) and a matching recorded packet fragment. A `FakeMatcher` with fixed
per-text scores and chunk spans from the real `semantic.chunk_spans`.

Tests: join (exact key match; one unjoined pair reported), role labelling for
every construction × arm × outcome cell in the ground-truth table, confusion
counts and localisation classes on constructed positive sets, the T2-bypassed
first-hit rule, the gate counterfactual under the three rules, chunk detail
(value chunk found and null when absent), the synthetic sweep using the real
`lcs_evidence` (excluded substring pairs, `truncated_to_sentence`), the
cross-check (`agree`, `differs`, `not_computed_by_variant`), HTML escaping of
values containing `<`, and output-directory refusal. Integration: run the CLI
over `runs/20260921-case-r-v1` when present with the model available and assert
46 recipient pairs, zero unjoined, and that every canonical recipient pair has
`first_matched_tier = tier2` with Tier 3/4 skipped.

## Commands

From `codebase/agentdojo-lab` (POSIX; on Windows use `.venv/Scripts/python.exe`
and `PYTHONUTF8=1`):

```bash
.venv/bin/python scripts/report_case_r_tiers.py \
  --batch runs/20260921-case-r-v1 \
  --packet reports/20260921-case-r-groq-v1/packet.json \
  --output reports/20260922-case-r-tier-diagnostic-v1
.venv/bin/python scripts/figure_case_r_tiers.py \
  --packet reports/20260922-case-r-tier-diagnostic-v1/packet.json \
  --output reports/20260922-case-r-tier-diagnostic-v1
```

Zero model requests in both commands.

## Out of scope

No Tier-1 transformation test (separate spec), no new Groq requests, no pilot
rows, no threshold changes, no replacement of LCS by substring in any frozen
module, no new tracer, no second task family. The synthetic length sweep is a
constructed supplement, not a new experiment protocol.
