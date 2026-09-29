# Decoded scalar span diagnostic

## Material Passport

- Origin Skill: academic-research-suite
- Origin Mode: bounded implementation and experiment planning
- Origin Date: 2026-09-09
- Verification Status: prospective engineering protocol; controls await execution
- Version Label: decoded-scalar-span-evidence-v1

## Purpose and scope

This offline diagnostic measures where lexical correspondence falls within a decoded tool-output
scalar. Its immediate question is whether a whole-result source candidate can be refined into
correspondence inside an assigned injection region, elsewhere in the scalar, or across competing
locations. It does not label the entire mixed tool result malicious.

This is a separately named diagnostic extension to the existing paper-based NeuroTaint implementation.
The online tracer, source/sink policy, detector thresholds, recorded whole-result scores and primary
agent requests remain unchanged. The extension reads only recorded proposal prefixes and writes new
derived artifacts. It neither blocks actions nor updates model weights.

The paper already compares source fragments and includes chunk-level matching, but it does not specify
this diagnostic's paired Unicode ranges or all-optimal lexical alignment accounting.
[NeuroTaint section 4.2](https://arxiv.org/html/2604.23374v1#S4.SS2)
Our additional coordinates are an implementation and measurement choice, not an omitted paper tier
or a new ninth acceptance gate.

## Evidence contract

Every source and target range is a half-open interval `[start, end)` in decoded Unicode codepoints.
Offsets are neither UTF-8 byte positions nor JavaScript UTF-16 code units. Preserve the exact scalar,
its JSON/YAML pointer and original result, request and event identities. Preserve the enclosing
serialized token range when the native adapter can validate one.

An enclosing wire-token range identifies the serialized scalar as a whole. It is not a one-to-one
alignment between decoded characters and raw serialization: escapes, quoting and multiline scalar
formats can change their lengths. Do not transform a decoded span into raw offsets by adding its
start to the token start. Unsupported or unverified parsing remains unavailable, rather than silently
rewritten evidence. A plaintext engineering fixture tests the lexical engine; it does not itself
validate the native serialization adapter.

Assigned injection regions are obtained from immutable experimental assignment and verified exposure
records. They identify where the supplied payload was observed, not whether that payload caused an
action. A source-level candidate alone never becomes an injected-span positive.

## Frozen lexical rules

- **Resource bounds:** each scalar has at most 8,192 codepoints, and the source-length times
  target-length product is at most 2,000,000. A larger comparison is unscored; do not truncate it
  silently or interpret missing evidence as a negative.
- **Literal evidence:** search for bounded exact occurrences of the complete target in the source
  using `exact_spans` with minimum length one. Preserve the existing lexical boundary rule; connected
  neighboring alphanumeric characters or `_@./:+-` disqualify an otherwise matching boundary.
  Classify a complete occurrence by whether it is wholly inside assigned regions, wholly outside,
  or crosses them. Aggregate competing inside/outside occurrences as ambiguous and any crossing
  occurrence as mixed. Emitted hits are capped at 256; incomplete evidence must remain explicit.
  This version does not search for arbitrary exact subphrases of a longer target.
- **LCS evidence:** retain the existing whole-scalar LCS result. For all alignments attaining the
  maximum LCS length, report the minimum and maximum numbers of matched source codepoints inside
  assigned regions. A zero maximum means no optimal alignment uses those regions; a positive minimum
  means every optimal alignment uses them; a zero minimum and positive maximum preserves ambiguity.
  This is a property of the lexical optimization problem, not a statement that the model relied on
  the region.
- **Low information:** flag a nonempty target of at most three codepoints, or a target consisting
  entirely of decimal digits. Preserve its evidence instead of silently turning it into a confident
  provenance verdict. This flag is a local diagnostic rule.
- **Semantics:** this extension provides no paraphrase detector, semantic reference label or causal
  judgment. Semantic and implicit influence remain unmeasured by these lexical outputs. An exact
  miss is not evidence that a longer target contains no reused subphrase.

## Prospective engineering controls

[`configs/SPAN-CONTROLS.json`](configs/SPAN-CONTROLS.json) fixes twelve handcrafted cases before
executing the diagnostic against them. They cover benign-only copy, injection-only copy, mixed
subsequences, mixed literal occurrences, shared identifiers, incidental letters, no overlap,
repeated-character alignment ambiguity, Unicode, clean empty regions, an authored paraphrase and
an escaped newline after decoding.

Expected LCS values were derived without importing or executing the new engine. The independent
enumeration procedure considers subsequence lengths from longest to shortest, enumerates source
index subsets and distinct target subsequences of that length, and retains every matching source
subset at the first nonempty length. Counting annotated source indices in all retained subsets gives
the expected minimum and maximum. The zero-length subsequence supplies a well-defined zero result
for disjoint strings. Full-target occurrences and lexical boundaries were checked directly.

The fixtures are authored by Codex. Their literal locations are known by construction, but they are
not independent human labels or estimates of real-agent attribution accuracy. In particular,
`incidental_letters` deliberately reaches LCS ratio 0.75 with no full-target literal match;
`authored_paraphrase` deliberately receives no semantic verdict. These examples prevent lexical
alignment terminology from being presented as semantic or causal ground truth.

Record a configuration hash before executing controls or analyzing saved traces. Keep that hash,
implementation identity, resource limits and all expected/observed discrepancies with the new result.
Native adapter controls separately verify decoded scalar identity, pointers, exposure ranges and
enclosing wire-token references. Existing experiment artifacts are immutable inputs.

The first adapter accepts complete recordings from the existing frozen task 29 pilot and input
comparison only. It reconstructs source and argument identities from events in order, checks the
saved sidecar bindings, and compares every policy-selected scalar argument with every decoded value
scalar in eligible visible tool sources. Nonselected arguments remain in JSONL with an explicit
status; the viewer shows selected arguments. Comments and mapping keys are not value scalars.
The recorded whole-message cascade metrics are copied, not recomputed as semantic evidence; a
digest links each compact metric record to its full saved pair. Decoding failures remain unavailable.
The run-wide limits are 4,096 comparisons and 20,000,000 cumulative source-target length products,
in addition to the per-comparison bounds. Skipped comparisons retain their identities and unknowns.
No target segmentation, arbitrary substring alignment or semantic span verdict is introduced here.

Each export freezes the explicit ordered historical input inventory, control hash and implementation
hashes before executing controls or analyzing traces. The first durable selection is all ten runs
from the completed pilot followed by all ten runs from the completed input comparison, in each
batch's frozen schedule order. This is retrospective development analysis; it neither pools native
attack success rates nor supplies a held-out estimate. No real model requests occur during export.

## Bounded completion and evaluation status

The current engineering package closes when all twelve fixtures are accounted for, native scalar
binding controls are checked, every selected saved-trace comparison is reported with availability and
limits, and new English HTML/JSONL evidence preserves the original inputs. Negative or ambiguous
results are deliverable outcomes. Do not adjust thresholds or cases to obtain preferred results.

The proposed held-out experiment in [`NEXT-STRATUM.md`](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/NEXT-STRATUM.md) has **not yet been executed**
under this diagnostic protocol. Its existing proposal is one prospectively selected native case,
excluding development cases, with five clean and five injected runs in a fixed passive condition.
Selection, assignment, schedule, code and budgets must be frozen before model inference. Retain all
planned slots, failed runs, unexposed payloads and unsuccessful attacks without replacement.

The final reproduction gate remains the independent evaluation already specified in
[`EVALUATION.md`](EVALUATION.md). Its frozen-label, independent review, adjudication, valid metrics,
ambiguity/abstention, ablation, timing, cost and negative-result requirements remain unchanged. The
paper also describes independently reviewed scenario labels; our particular field/span review format
is a local protocol choice. [NeuroTaint section 5.1 and Appendix B.2](https://arxiv.org/html/2604.23374v1)

Do not ask the owner to repeat the twenty completed assisted-review items. Preserve them as development
evidence with their declared authorship. If independent reference labels are unavailable, close the
engineering and descriptive reporting work while leaving independent precision/recall/F1 null and
gate 8 unaccepted. Neither a successful attack nor a protective effect is required to finish a planned
experiment. Matching the paper's original tables, adding action blocking or completing a new defense
framework is outside this package's acceptance scope.
