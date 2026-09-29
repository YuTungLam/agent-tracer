# Migration record

Date: 2026-09-29

Agent Tracer was assembled as a fresh-history repository. The old checkout was not edited, committed, rebased, merged, or cleaned in place.

## Imported sources

| Source ref | Commit | Imported content |
| --- | --- | --- |
| codex/propagation-testbed | e76c03552e2b72531f1e0efe14d56ecbd31aca1a | packages/tool-output-lab |
| codex/langgraph-foundations | 2f73aabfe1633e456a82ed938e5eb42f5fa41cf3 | examples/langgraph-agent |
| codex/agentdojo-lab | f761e0883452a1c52234d92978ca4511ac4bea51 | packages/agentdojo-lab |

The propagation branch already contains main at 7383036f31821dfb9639d663627c6faf43ed8003 and the attack taxonomy branch at 4ae1fa26c5547118291aca2179514ba0b5dd301b. Importing those refs separately would duplicate content. The obsolete local test branch was not imported because its unique files are generated literature/deck outputs rather than current code.

Exact changed-path overlap between the three imported lines was zero. Their architectural overlap remains: each has its own tracing layer and packaging strategy.

## Excluded material

The AgentDojo source tree at the imported commit contained 16,457 files and 732,258,857 logical bytes. These two generated directories accounted for 15,947 files and 723,583,271 bytes:

| Path | Files | Bytes | Git tree |
| --- | ---: | ---: | --- |
| codebase/agentdojo-lab/runs | 14,418 | 480,717,682 | b4b561073eb0a71be7672f33f2c64b43d1e40d46 |
| codebase/agentdojo-lab/reports | 1,529 | 242,865,589 | 99d6e357198c818ab5653d26e49ebc7d511d6001 |

Removing them cuts 98.8% of the AgentDojo snapshot's bytes. Also excluded:

- scheduler logs, local virtual environments, caches, downloaded vendor code, and package metadata;
- generated result Markdown, progress ledgers, handoff/closeout notes, and an implementation-plan journal;
- the completed assisted-label dataset and result-specific review notes;
- eight stashed raw trace JSONL files and generated boundary_agent.egg-info metadata;
- the obsolete local test branch.

The eight HTML/template assets under packages/agentdojo-lab/src/agentdojo_lab were retained because application code loads them.

Some frozen experiment configs still name historical result files. They are retained as protocol records, but those evidence paths resolve only in the immutable source archive.

## Results archive

The excluded experimental evidence was copied, without rewriting the source checkout, to the private [agent-tracer-results](https://github.com/YuTungLam/agent-tracer-results) repository:

- commit: `ed716be6c1bbfa37706b17513a76de65f4b9a289`;
- branch: `main` only;
- historical files: 15,988;
- historical logical size: 724,167,433 bytes;
- reachable packed Git data at migration time: approximately 25 MiB.

The archive preserves the exact runs, reports, and annotations tree objects, selected result and progress records, research/HPC context, scheduler logs, and the eight unpublished stash traces. Reusable source changes from the stash were incorporated into this code repository; generated package metadata was not archived.

## Recovered local work

The source checkout had a local stash based on an older AgentDojo commit. Its HTML temporary-file fix was already superseded upstream. The still-relevant changes were replayed here:

- explicit UTF-8 reads and writes in bootstrap, runner, CLI, and reporting paths;
- installation of the figures extra during bootstrap;
- a platform-correct dojo-lab executable hint.

The unconditional POSIX fcntl imports in four current modules were replaced with a small Windows/POSIX advisory-lock adapter.

## History and branches

The new repository began with one consolidation commit and keeps `main` as its only long-lived branch. This follow-up documentation records the private results boundary. No source branch, pull-request ref, generated artifact, or old Git history was pushed here. The old remote branches were not deleted; they remain the historical record.

## Known follow-up work

The import preserves behavior instead of attempting a high-risk rewrite. Future cleanup should:

- extract one canonical tracing/event schema used by all integrations;
- parameterize the duplicated Case B/C/C2/D/E and repeat/multi-repeat HPC runners;
- consolidate OpenAI-compatible provider adapters;
- move protocol-specific scripts under a clear experiments namespace;
- define one workspace-level dependency and CI strategy;
- add an explicit project license, contribution guide, and security policy.

The source repository was already public. Its historical review-key mapping and raw evidence must be treated as disclosed; any study that depended on continued blinding should be reviewed or reblinded.
