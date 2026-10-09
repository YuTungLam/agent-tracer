# H3 two new stock-task development candidates (offline preparation)

This after-data exploratory preparation is independent of
`H3-PAIRS-V1.md`. The proposed candidate registry is
`configs/h3_pairs_v2.json`; it adds Banking `user_task_0` (bill recipient from
`read_file` into `send_money.recipient`) and workspace `user_task_29` (file ID
from `search_files_by_filename` into `append_to_file.file_id`). Neither task
is the previously observed Slack `user_task_2` case or the held-out Banking
`user_task_2` evaluation case. Both new template IDs hash to `dev` under the
existing split salt. The old frozen SS protocol used a different **task-key**
hash; both tasks also hash to `dev` by that rule. Hash eligibility and old
registry membership are separate facts:

| Task | Old key's first SHA-256 byte | New H3 template's first byte | Old frozen SS member? |
| --- | ---: | ---: | --- |
| Banking `user_task_0` | 90 (`dev`) | 242 (`dev`) | **No** |
| Workspace `user_task_29` | 156 (`dev`) | 138 (`dev`) | Yes, as an SS seed; this H3 pair is new |

The old key is `task:{suite}/{user_task_id}`; the new key is
`h3:{suite}:{user_task_id}:{function}.{argument}`, both with the
`authority-auditor-pilot-v1|` salt. Banking `user_task_0` was **not** in the
old frozen SS registry despite its `dev` hash. It is an after-data exploratory
extension and is ineligible for any original confirmatory claim based on old
SS membership. Neither new H3 pair changes the old registry or enters the
old SS results. V1 inputs and archived results remain separate.

Each pair changes only the trusted user request by appending the exact
legitimate authority value **L**. The stock task, initial environment,
tool-returned data, ground-truth calls, target sink, and native utility are
the same in both arms. The local validator checks the native prompt,
environment and call hashes, L exposure in the declared source tool output
before the sink, target call with L, and native utility. The v2 test also
checks these invariants on both new cases. Workspace `user_task_29` updates
the file's live `last_modified` timestamp, so raw final-state hashes can differ
between two otherwise identical ground-truth runs. An offline diagnostic
found only the two mirrored timestamp fields differed; raw final-state hash
equality is therefore not a pair admission rule. These are AgentDojo
ground-truth checks with **zero model calls**. They cannot show that a model
will propose L, that undefended utility remains within 10 percentage points,
or that an auditor falsely blocks it.

The registry is a candidate list for an independent, dev-only preparation;
it is not an H3 effect estimate or a full main-study registry. In particular,
the old evaluation task remains held out, and no evaluation environment is
built or run by this v2 list. The workspace candidate may be expensive under
ARGUS Warrant, as the earlier workspace `user_task_35` experiment failed its
episode ceilings three times. Estimate audit work and set a hard guard before
any separate live stage; never pool those invalid rows into v2.

Run the no-provider checks from the code repository with the lab interpreter:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
& 'packages/agentdojo-lab/.venv/Scripts/python.exe' -B -m unittest `
  discover -s packages/agentdojo-lab/tests -p test_h3_pairs_v2.py -v
```

After committing the source and config, use `scripts/generate_h3_pairs.py`
with `--config configs/h3_pairs_v2.json` and a **new** experiment directory
under the confirmed private results checkout. The script refuses a dirty
source tree and existing output directory. Record the exact code commit,
configuration hash, input byte hashes, checksums and predecessor IDs in that
new experiment's manifest. This document does not authorize model calls.
