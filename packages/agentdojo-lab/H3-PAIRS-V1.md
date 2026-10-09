# H3 stock task pair preparation (after-data exploratory)

The original pilot protocol, §1.1 and §4.3, defines H3 as the difference in
false blocks between a benign task whose legitimate authority value **L** comes
from tool data and the same task with **L** also stated in the user prompt. This
preparation uses stock AgentDojo v1.2.2 tasks, no attacker text, and no model
requests. It is exploratory after D26/D27; it does not convert those results into
an H3 test.

The registry is `configs/h3_pairs_v1.json`. Each natural `template_id` fixes one
stock task and one sink argument. The §8.4 SHA-256 split is recomputed from that
new `template_id`, independently of the older H2/SS split. The registry currently
has two dev templates, workspace `user_task_35` (file id `11`) and Slack
`user_task_2` (Dora's e-mail), plus banking `user_task_2` (scheduled transaction
id `7`), whose natural id hashes to **eval**. The generator records the banking
split but does not build or run its environment. No eval episode enters the plan.

For each dev candidate, the generator checks the stock prompt exactly, the
native GT call chain, the source tool output exposing L before the sink, the sink
argument, identical initial environments and GT calls across arms, the same
native utility implementation, and true native utility. It records hashes of
both prompts, initial environments, GT calls, and the utility implementation.
These local checks establish fixture consistency. GroundTruthPipeline follows
canonical tool calls regardless of prompt wording, so they **cannot** establish
that an undefended model will keep utility after the sentence is added. The
protocol requires the relocated arm's measured undefended utility to be within
10 percentage points of the original before H3 is interpretable.

Once this source and config are committed, create immutable evidence in the
confirmed results checkout:

```powershell
& 'G:\GitHub\agent-tracer\packages\agentdojo-lab\.venv\Scripts\python.exe' `
  'G:\GitHub\agent-tracer\packages\agentdojo-lab\scripts\generate_h3_pairs.py' `
  --results-root 'G:\GitHub\agent-tracer-results' `
  --out-dir 'G:\GitHub\agent-tracer-results\experiments\<new-h3-id>\derived\h3-prep' `
  --repeats 5
```

The output contains `h3_pairs.json` and a machine-readable, **dev-only**
`h3_plan.json`: 2 pairs × 2 arms × 5 repeats = 20 proposed episodes if both
dev cases pass the offline checks. It records the exact code commit and config
hash. The plan is **not** accepted by the H2 attack runner: H3 needs a dedicated
benign false-block scorer and prompt override handling, followed by a new
after-data stage with budget and stop criteria. Do not feed it to the H2
same-source/ADI attack summary or infer an H3 effect from GT checks.
