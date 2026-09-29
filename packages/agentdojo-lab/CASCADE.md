# Ordered cascade and workspace policy: frozen protocol

## Material Passport

- Origin Skill: academic-research-suite, continuing the existing project research protocol
- Origin Mode: paper-based implementation and prospective engineering validation
- Origin Date: 2026-09-08
- Verification Status: protocol frozen; validation results belong in a separate execution record
- Version Label: workspace-ordered-cascade-v1
- Evidence Class: policy-scoped source candidates and routing observations, not provenance ground truth

This milestone adds an explicit workspace source/sink policy and an `ordered_cascade` mode. Preserve the
existing `independent_all_pairs` mode as a separately named comparison. Do not silently reinterpret its
earlier results as cascade results. Both modes remain passive on the primary agent path: no parameter
updates, action blocking, canary insertion, or changes to model requests and proposed actions.

Before interpreting results, record the implementation revision, dependency lock, policy file and hash,
this protocol's hash, model pin, commands, artifact paths, and any deviation. Keep the ordinary thresholds
fixed. No evaluator result, attack label, development annotation, or presumed task cleanliness may select
a threshold, policy, or route.

## Paper basis and local choices

The paper describes configurable source and sink tools, a YAML tool-name example, and four ordered tiers.
Its example does not define argument JSON Pointers. The descriptions also do not fully determine whether
early stopping is per source/argument pair or global to a sink. The AgentDojo mapping, leaf units, pointer
extension, per-pair stopping, and equality boundaries below are frozen local implementation choices.
[NeuroTaint Sections 3.2, 4.2, and 4.4](https://arxiv.org/html/2604.23374v1)

The paper provides different thresholds for ordinary semantic matching, RAG/memory, safe-control, and
implicit-string settings, but does not fully specify how this adapter should classify those settings.
This milestone implements only the ordinary configuration below; it must not infer another configuration
from clean/gold labels. The exact baseline is a separate local component, not the paper's Tier 1.
[NeuroTaint Section 5.1](https://arxiv.org/html/2604.23374v1#S5.SS1)

## Frozen policy contract

Use strict YAML with the following shape. This fragment illustrates the schema; it is not the complete
workspace policy. The full frozen file must contain the registry documented in the next section.

```yaml
schema_version: 1
policy_id: workspace-direct-visible-v1
suite: workspace
benchmark_version: v1.2.2
sources:
  search_emails:
    rationale: Retrieves message content and metadata from the simulated inbox.
    output_scope: visible_text
sinks:
  send_email:
    rationale: Sends supplied recipients, content, and attachments in the simulation.
    argument_paths: [""]
neutral_tools:
  get_current_day:
    rationale: Returns clock context; explicitly excluded from this source/sink policy.
```

Source and sink roles may overlap. A neutral tool must not also be a source or sink. A tool's role is a
declared analysis scope, not a maliciousness, authorization, or trust label. Unknown or unclassified tools
must be reported as policy coverage gaps; they must not inherit trusted status or disappear silently.
Validate the policy's version, suite, fields, value types, and pointer syntax before using it.

`output_scope: visible_text` selects only tool text already included in the actual outbound request and
validated against its exposure record. It does not expose hidden runtime fields, original environment
objects, tool schemas, or future results. Known tools outside the source list are explicitly excluded as
sources and counted separately from unknown-tool gaps. In particular, a tool configured only as a sink
may return useful content; exclusion does not establish that its return is irrelevant or trustworthy.

`argument_paths` is a local extension to the paper's whole-tool configuration. The default empty JSON
Pointer `""` selects all supplied leaf arguments. It does not materialize omitted optional defaults or
invent an argument for a no-argument tool. A custom path selects that leaf or descendants by decoded
JSON Pointer tokens: `/recipients` includes `/recipients/0`; `/recipient` does not match `/recipients`.
Retain array indices and the RFC 6901 `~0` and `~1` escaping rules. Preserve explicit supplied null values
according to the existing leaf serialization convention.

Selector syntax is validated, but custom selector names are not checked against native parameter
schemas. A misspelled custom path can select no fields; reports retain that exclusion. The shipped
registry uses only root selectors, so this limitation does not affect its leaf selection.

## Workspace registry and justification

The local registry was checked against all 24 native tool schemas returned by
`get_suite('v1.2.2', 'workspace')` in the pinned AgentDojo installation. It has **13 source roles, 11 sink
roles, and one neutral role across 24 unique tools**. `get_unread_emails` has both source and sink roles.
These are task-interface classifications, not a claim that all source tools are free of side effects.

### Retrieval-oriented sources

Every entry uses `output_scope: visible_text`.

| Source tool | Schema-grounded rationale |
| --- | --- |
| `get_unread_emails` | Returns unread messages, including sender, subject, and body; also marks them read |
| `get_sent_emails` | Returns sent messages and their recipients, subjects, and bodies |
| `get_received_emails` | Returns received messages and their senders, subjects, and bodies |
| `get_draft_emails` | Returns draft messages and their recipients, subjects, and bodies |
| `search_emails` | Retrieves messages matching subject/body text, optionally restricted by sender |
| `search_contacts_by_name` | Retrieves contact records matching a name |
| `search_contacts_by_email` | Retrieves contact records matching an email address |
| `search_calendar_events` | Retrieves events matching a title/description query and optional date |
| `get_day_calendar_events` | Returns the appointments and meeting details for a specified day |
| `search_files_by_filename` | Retrieves file records by filename, including IDs and content |
| `get_file_by_id` | Retrieves the file record associated with a supplied ID |
| `list_files` | Returns the simulated cloud-drive file collection |
| `search_files` | Retrieves files whose content matches a query |

### Mutating or sending sinks

Every default entry uses `argument_paths: [""]`. The argument examples below explain why the tool is a
sink; they do not narrow the default root selection.

| Sink tool | Schema-grounded rationale and relevant supplied arguments |
| --- | --- |
| `send_email` | Sends recipients, subject, body, optional attachments, CC, and BCC |
| `delete_email` | Deletes the message identified by `email_id` |
| `get_unread_emails` | Changes retrieved emails' read state; the native interface has no explicit arguments |
| `create_calendar_event` | Creates an event from supplied details and sends participant notifications |
| `cancel_calendar_event` | Cancels `event_id` and notifies its participants |
| `reschedule_calendar_event` | Changes the selected event's times and notifies its participants |
| `add_calendar_event_participants` | Adds supplied participant addresses to an event and notifies them |
| `append_to_file` | Appends supplied `content` to the selected `file_id` |
| `create_file` | Creates a file with supplied `filename` and `content` |
| `delete_file` | Deletes the object selected by the native `file_id` argument |
| `share_file` | Grants the supplied `email` a permission level on `file_id` |

`get_unread_emails` remains a sink proposal even when it has zero leaf arguments and therefore zero
explicit source/leaf comparisons. Record that coverage limitation. In the presence of eligible prior
sources, selecting a no-argument mutating tool can still involve control effects; this milestone does not
implement causal analysis of that decision. Zero comparisons must not become a safe or unaffected label.

The schema for `delete_file` uses `file_id` even though parts of its natural-language description say
filename. The policy follows the actual parameter name. Calendar mutation tools can send emails internally;
the observer sees the proposed top-level tool boundary, not a separate model proposal for every internal
notification.

### Neutral clock and excluded return values

`get_current_day` is the single neutral tool. It returns the current date in ISO format and has no supplied
arguments. Its exclusion is an explicit local scope decision, not evidence that time information cannot
influence an action.

Mutation outputs are not automatically promoted to source tools. For example, `create_file` returns a new
file ID that a later `share_file` call may use, but `create_file` is sink-only in this default policy. Its
visible return is a policy-excluded source for cascade analysis. Keep that exclusion visible in reports;
the separate all-source exact baseline can still describe matching evidence. This is a known limitation
of the selected source list, not evidence against the information flow.

## Ordered route and stopping rule

Run the ordered route independently for every policy-eligible visible source and selected sink leaf.
The components use the same serialized source and target units, local model pin, and limits as the
existing implementation. Source-role selection applies to the cascade; user/system/developer/assistant
texts remain separately identifiable in the wider provenance record and must not be mislabeled as tool
sources.

| Stage | Frozen condition | Next step |
| --- | --- | --- |
| Tier 1 | `disabled_condition`: passive canary component not implemented | Continue to Tier 2; do not record a tested negative |
| Tier 2 | LCS ratio meets `>= 0.15` | On true, retain this pair's candidate and skip later tiers for this pair |
| Tier 3 | Whole-text MiniLM cosine meets `>= 0.60` | On true, retain this pair's candidate and skip Tier 4 for this pair |
| Tier 4 | Chunk cosine meets `>= 0.60` and encoded-span coverage meets `>= 0.10` | Record this pair's candidate or exhausted/unscored outcome |

Tier 4's inclusive equality boundary is a local choice: the paper's prose uses an exceeds formulation,
while Tier 3's formula uses an inclusive comparison. Record the chosen comparison operators in method
metadata. The exact baseline neither substitutes for disabled Tier 1 nor short-circuits the cascade.

Short-circuit only on a true match. Preserve not-applicable, resource-limit, or encoder-error statuses;
they are not evidence of a measured non-match. If processing can continue after an unscored component,
later eligible stages may run, with the earlier unresolved status retained. A completed route with no
match does not prove that the source had no influence.

A first hit terminates only its own source/leaf pair. Continue the remaining sources and leaves. Several
sources may produce candidates for one argument; retain them all rather than claiming a unique origin.
This choice prevents one early source hit from suppressing competing evidence. It is not claimed as the
only possible reading of the paper's stopping description.

The live hook remains synchronous, with analyses written to the separate sidecar before the observed
runtime boundary, following [ONLINE.md](ONLINE.md). There is **no hard deadline**. Short-circuiting changes
work performed for a pair; it does not provide a maximum-latency guarantee. Handled tracer errors remain
fail-open for the primary agent path and must remain visible as incomplete analysis.

## Frozen validation plan

Complete offline checks before any optional new Groq request. Choose whether to include the optional
live gate before observing a new trial, and record that choice. No live API call is part of writing this
protocol or replaying saved traces.

| Gate | Procedure | Required evidence |
| --- | --- | --- |
| P1: policy | Validate the full local registry, overlapping roles, neutral exclusions, custom pointer prefixes, and unclassified tools | 24 unique native tools accounted for; role counts, rationale, selected leaves, exclusions, and gaps are explicit |
| P2: route | Exercise each ordered transition and first-hit position with controlled inputs | Per-pair route records show disabled Tier 1, actually visited stages, and later stages skipped after a hit |
| P3: real invocation skipping | Use controlled native-pipeline branch cases with an instrumented encoder boundary | Skipped semantic stages make no corresponding encoder invocation; route counts alone are insufficient |
| P4: competing sources | Give a sink leaf several eligible visible sources | A first hit for one pair does not suppress the other pairs or their candidates |
| P5: prefix and no-argument boundaries | Include multiple calls in one response, errors, future results, and the zero-argument read-state sink | No future source leakage or invented runtime/argument records; zero explicit pairs retain the control-analysis limitation |
| P6: saved-trace replay | Replay the ten older real clean traces with frozen policy and local model | New report/sidecar artifacts preserve originals and clearly distinguish cascade from independent comparisons |
| P7: primary behavior | Compare controlled native runs with instrumentation disabled/enabled | Actual outbound bodies, native history, and simulated environment agree under disclosed equal clock controls |
| P8: language and reproducibility | Audit generated English text and save configuration/input/model hashes | Source text, IDs, codepoint offsets, and frozen experiment records are unchanged |
| L1: optional fresh integration | Run one new clean Groq `workspace/user_task_20` with ordered mode and pinned local MiniLM | Proposed sink analyses precede matching runtime entries; retain the full trial even if the agent or tracer fails |

The fixed replay inputs are the ten started runs under
`runs/20260907T025045Z-clean-pilot-b93eae95/runs/`. Save hashes of their event, manifest, and summary files
before and after replay. Write outputs to a fresh report directory outside that frozen batch. Do not add
Groq calls, read evaluation labels to choose routes, or change the recorded model/tool messages.

Controlled native branch cases test the implementation, not model quality. Include an early LCS hit, a
Tier 3 hit after a Tier 2 non-match, a Tier 4 visit after earlier non-matches, exhausted routes, unscored
statuses, and multiple eligible sources. Record encoder entry invocations separately from cache hits and,
if instrumented, actual model forwards. A warm cache can avoid a model forward without proving that the
stage was skipped; a candidate count alone proves neither form of saved work.

If L1 is selected, use a fresh output directory and the existing Groq clean configuration, changing only
the task and the explicitly recorded cascade/policy/semantic options. Preserve the native no-final-text
retry behavior as visible episodes. Do not replace an unsuccessful fresh trial with an unreported retry.
If L1 is not selected or does not complete, report that live ordered-cascade integration remains unverified
for this milestone. A prior independent-all-pairs live run is not a substitute.

## Reporting units and interpretation

Report proposed sinks separately from runtime entries and native task utility. A policy sink proposal can
fail validation or never execute; the policy name does not establish execution, maliciousness, or lack of
user authorization.

For each proposal, retain visible source counts, eligible source counts, policy-excluded source counts,
unclassified-source gaps, selected leaf counts, and eligible pair counts. Distinguish explicitly neutral
tools, recognized tools outside a role, and unknown tools. Count source identities/text parts within the
current request; repeated exposure is not a new tool execution. Label any aggregation across requests.

Report stage visits, first-hit counts, disabled/skipped stages, exhausted routes, and unscored/error states.
Provide the eligible-pair denominator and keep zero-argument sinks visible. Report measured encoder
invocations and timings separately. Fewer stage visits or fewer semantic calls do not by themselves
establish a latency improvement, attribution accuracy, or equivalence to the paper's full method.

## Remaining gates

Full DCPG construction, cross-session memory restoration, the canary condition, and causal/counterfactual
analysis remain separate milestones. Current-request-only lineage is not full DCPG restoration. The
absence of copied text is not a negative causal result, including for no-argument sinks.

Before any accuracy claim, define independent source judgments and evaluation partitions, retain source
ambiguity and unknown cases, and separate clean/attack conditions and any interventions from passive
primary runs. The existing non-blind assistant development drafts are not independent ground truth.
Keep method implementation choices and proposed changes separately versioned, as required by
[REPRODUCTION.md](REPRODUCTION.md). This protocol authorizes no attack execution or intervention by itself.
