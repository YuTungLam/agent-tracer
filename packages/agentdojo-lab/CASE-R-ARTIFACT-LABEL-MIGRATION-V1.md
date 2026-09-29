# Case R artifact-label migration v1

Date: 2026-09-29. This migration gives the active Case R diagnostic files,
protocol IDs, scripts, report directories and cross-links descriptive names.
It does not change the original Groq trajectories or the fixed MiniLM scorer.
The predecessor bytes remain recoverable in Git commit `ba4ebe98`; the active
tree contains the normalized labels.

| Artifact role | Current artifact |
| --- | --- |
| Recipient-context crossover | [protocol](CASE-R-RECIPIENT-CONTEXT-CROSSOVER-OFFLINE-V1.md) · [report](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260929-case-r-recipient-context-crossover-offline-v1/index.html) |
| Duplicate-address control | [protocol](CASE-R-RECIPIENT-DUPLICATE-CONTROL-OFFLINE-V1.md) · [report](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260929-case-r-recipient-duplicate-control-offline-v1/index.html) |
| Original asymmetry audit | [protocol](CASE-R-ORIGINAL-ASYMMETRY-AUDIT-V1.md) · [report](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/reports/20260929-case-r-original-asymmetry-audit-v1/index.html) |

Exactly 11 file/directory paths and 19 tracked text files carried the prior
reviewer-specific label. Their active names, internal IDs and links were
normalized. Packet checksums that refer to other packets were then updated
in dependency order: crossover, duplicate control, original audit. Source
texts, diagnostic targets, chunk texts, all numeric values, and all booleans
were compared recursively with their predecessor JSON objects in Git.

| Packet role | Before SHA-256 | Active SHA-256 | Numeric fields | Source/target/chunk strings |
| --- | --- | --- | ---: | ---: |
| Crossover | `346d9a210bedbd7fe4b43b61bb3bfa6b991c7008637d1ed61275e768865e7835` | `48505bd691c22bc59cde27d9b6f237eae86eefb088a8749f139528e23b66d8f9` | 19,572 identical | 724 identical |
| Duplicate control | `1462582809cc47b3c75d90eeff6b1fa0b061270507f6e043e7ba16b0e0c2c1a7` | `d14f134d546783b45e4c2688db7f3d3c13de4dc8821f9f7997c4414df900f125` | 661 identical | 24 identical |
| Original asymmetry audit | `ab3b673dbf449b4a5fa753bb3c4cd68562a47f7878b503030f3bca0122c371e1` | `a6feac4eb1488bca306e2039b2245ae24ab2e179b7a814ae774313e9d4467f4c` | 786 identical | 22 identical |
| Crossover preflight | Historical packet in Git | [active packet](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/runs/20260929-case-r-recipient-context-offline-preflight-v1/packet.json) | 19,553 identical | 724 identical |
| Duplicate preflight | Historical packet in Git | [active packet](https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems/blob/f761e0883452a1c52234d92978ca4511ac4bea51/codebase/agentdojo-lab/runs/20260929-case-r-recipient-duplicate-preflight-v1/packet.json) | 659 identical | 24 identical |

The original source/sink evidence, scored outcomes and failed preflight
interpretations retain their scientific meaning. The preflight packet bytes
in the active tree differ only in labels and dependent packet hashes; their
original byte versions remain available at the predecessor commit. Future
protocols use experiment-content names. Fixture names inside the frozen Case R
source text are experimental inputs and are intentionally unchanged.
