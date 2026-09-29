# Results repository

Agent Tracer separates reproducible code from experimental evidence:

- [agent-tracer](https://github.com/YuTungLam/agent-tracer) is the public, compact, main-only code repository.
- [agent-tracer-results](https://github.com/YuTungLam/agent-tracer-results) is the private, main-only evidence repository.

This separation keeps normal clones and code review small while allowing access control for prompts, tool arguments and output, URLs, model responses, annotations, review mappings, logs, and rendered reports. Private Git storage reduces accidental exposure; it is not a substitute for privacy review or secret scanning.

The historical import is anchored at results commit `ed716be6c1bbfa37706b17513a76de65f4b9a289`.

## First-session handshake

An agent must not guess where the private checkout lives or clone it without instruction. Before the first result-related task in each new session, it must ask:

> Please provide or confirm the absolute path to your local `agent-tracer-results` checkout.

After confirmation, verify the Git root, a remote identifying `YuTungLam/agent-tracer-results`, branch `main`, and working-tree status. Read the results repository's `AGENTS.md` and `DATA_POLICY.md`, preserve existing changes, then use the confirmed path as `AGENT_TRACER_RESULTS_ROOT` for that session. This variable is a convention; pass the selected experiment directory to each command rather than assuming every script reads it automatically.

Without a confirmed checkout, agents may edit code, tests, fixtures, and experiment definitions, but must not launch or resume a run that creates evidence.

## Ownership boundary

Keep in `agent-tracer`:

- implementation and tests;
- small, intentionally hand-authored test fixtures;
- experiment definitions and schema templates;
- documentation that contains no generated evidence.

Keep in `agent-tracer-results`:

- raw traces and provider/tool responses;
- annotations and review mappings;
- derived datasets, tables, figures, and rendered reports;
- scheduler logs, checkpoints, run metadata, and checksums.

Never store API keys, tokens, `.env` files, credentials, identifiable user data, or unsanitized provider responses containing secrets in either repository.

## Experiment layout

Use one immutable directory per completed experiment:

```text
experiments/<YYYYMMDD>-<short-name>/
├── README.md
├── manifest.json
├── config/
├── raw/
├── derived/
├── reports/
├── logs/
└── checksums.sha256
```

`manifest.json` should record at least: experiment ID and schema version; Agent Tracer repository URL and exact code commit; frozen configuration hash; creation timestamp; runner/environment metadata needed for reproduction; artifact paths, byte sizes, and SHA-256 values; access classification and retention policy; and external storage URIs where applicable. Record the results commit and experiment ID in any publication or review handoff.

Historical imports remain under `snapshots/<source-id>/` so provenance is explicit and they cannot be mistaken for new runs. Do not rewrite finalized experiment directories; add a corrected experiment with a new ID and document its predecessor.

## Storage and scale

Git is reasonable for manifests, reports, and the current highly compressible archive when every file remains within host limits. It does not scale well to repeated large model outputs or unbounded new runs. For large future bundles, use access-controlled object or institutional research-data storage and keep only the manifest, checksum, size, access classification, and immutable storage URI in `agent-tracer-results`. Do not add Git LFS or another storage service without the user's approval.

On Windows, the historical snapshot has deep paths. Use a sparse checkout by default and set `core.longpaths=true` before materializing it.

## Historical disclosure

The former public source repository already contains historical evidence and a blinded-review mapping. Moving copies into the private results repository improves the future boundary but does not retract that disclosure. Treat the old public commit as an immutable provenance source, not the active results workspace.
