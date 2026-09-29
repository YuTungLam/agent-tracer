# Experimental data

Generated evidence is deliberately stored outside Agent Tracer.

## Immediate archive

The immutable source commit is:

- repository: https://github.com/YuTungLam/Tool-Output-Injection-Attacks-on-Agentic-AI-Systems
- commit: f761e0883452a1c52234d92978ca4511ac4bea51
- runs tree: b4b561073eb0a71be7672f33f2c64b43d1e40d46
- reports tree: 99d6e357198c818ab5653d26e49ebc7d511d6001

This is a provenance anchor, not a recommended permanent data store. The repository is public and historical evidence includes full prompts, tool output, model responses, URLs, adversarial payloads, and a blinded-review source mapping. Treat that mapping as already disclosed.

## Recommended long-term storage

Move evidence to access-controlled object or research-data storage after a privacy and licensing review. Store one manifest row per immutable experiment bundle with:

- artifact ID and schema version;
- source-code commit and frozen config hash;
- SHA-256 and byte size;
- storage URI;
- creation timestamp;
- access classification and retention policy.

Prefer compressed, checksum-addressed bundles over thousands of small Git objects. Do not place API keys, environment files, provider responses with secrets, or identifiable user data in either the bundle or its manifest.

## Local output policy

The repository ignores runs, reports, outputs, artifacts, annotations, traces, scheduler logs, caches, and local databases. Runtime HTML templates remain tracked. If a small fixture is required by a test, keep it under the test tree and document why it is source rather than evidence.
