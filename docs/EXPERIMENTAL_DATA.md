# Experimental data

Generated evidence is deliberately stored outside Agent Tracer.

## Active private archive

- repository: https://github.com/YuTungLam/agent-tracer-results
- branch: `main`
- historical import commit: `ed716be6c1bbfa37706b17513a76de65f4b9a289`
- imported files: 15,988
- imported logical bytes: 724,167,433

The archive preserves the source `runs` and `reports` trees, completed annotations, result/progress records, research and HPC context, scheduler logs, and eight unpublished local-stash traces. Its manifest records exact paths, counts, sizes, and tree IDs.

The repository must remain private. Evidence includes full prompts, tool output, model responses, URLs, adversarial payloads, realistic benchmark identities, and a blinded-review source mapping. A credential-pattern scan found no recognizable token, private-key, or bearer-token signatures, but that is not a guarantee that all private data has been identified.

Follow [RESULTS_REPOSITORY.md](RESULTS_REPOSITORY.md) for the first-session path handshake, ownership boundary, experiment layout, and Windows sparse-checkout guidance.

## Public provenance anchor

- repository: https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems
- commit: `f761e0883452a1c52234d92978ca4511ac4bea51`
- runs tree: `b4b561073eb0a71be7672f33f2c64b43d1e40d46`
- reports tree: `99d6e357198c818ab5653d26e49ebc7d511d6001`

The source repository was already public. Moving copies to the private archive does not retract the historical evidence or reblind its review mapping.

## Future storage

Keep one manifest per immutable experiment with the exact code commit, frozen config hash, SHA-256 values, byte sizes, timestamps, access classification, and retention policy. Git is acceptable for the present highly compressible archive, but unbounded raw output should move to access-controlled object or institutional research-data storage. Commit only its checksum-addressed manifest and immutable URI. Do not add Git LFS or a storage service without user approval.

## Local output policy

This code repository ignores runs, reports, outputs, artifacts, annotations, traces, scheduler logs, caches, and local databases. Runtime HTML templates remain tracked. If a small fixture is required by a test, keep it under the test tree and document why it is source rather than evidence.
