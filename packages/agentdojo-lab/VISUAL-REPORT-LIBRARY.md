# Visual Report Library

The visual library is the navigation entry point for current and historical
saved reports. Open `reports/visual-library-v1/index.html` in a browser, or use
the lab's existing local HTTP server:

`http://localhost:8766/reports/visual-library-v1/index.html`

## Covered report types

- **Visual run:** a new self-contained run view generated from its saved
  manifest, summary, recorded events, native traces, and available provenance.
  The interactive event route opens human-readable event cards, source details,
  and tool arguments. Existing timeline, architecture, and raw-evidence views
  remain available. Absent events and incomplete runs remain visible.
- **Visual comparison:** a new paired report available below the library's
  `paired/` directory. The paired-report requirements are defined in
  [PAIRED-REPORT-VISUALIZATION.md](PAIRED-REPORT-VISUALIZATION.md).
- **Archived report:** an original aggregate analysis, audit, replay, meeting
  packet, or other report without a supported single-run schema. These cards
  link to the preserved original HTML. Adding them to the catalog does not
  redesign their contents or update their historical interpretation.

The catalog offers text search and category/view filters. Cards report observed
event and model-request counts when the underlying record supports those counts.
Execution status, native task utility, and attack success are distinct concepts.
A completed run is not necessarily a successful task or attack.

The final single-run snapshot found **377 source HTML reports**, excluding seven
source templates and all frozen-runtime copies. **251 directories** were eligible for
the single-run exporter: each has a manifest and summary plus recorded events or
an explicit run-mode/event-recording manifest field. Other manifest/summary pairs
include aggregate experiment bundles and auditor outputs; treating those as
single agent executions would be misleading. These discovery counts may change;
the generated `inventory.json` records actual coverage and any export errors.

The completed single-run snapshot contains **251 visual run copies**, including
the six newly completed Case A v6 and Case B v4 runs. Each of those six saved
summaries reports `status: completed` and `recording.complete: true`; this is
execution-record completeness, not an assessment of task or attack success.
The catalog has **393 cards**: 377 original report locations plus 16 supported run
directories that had no original HTML. New paired views replace their source
reports' catalog destinations while retaining original-HTML links; they do not
add duplicate cards. The generated inventory records the current paired-view and
remaining archived-report counts after the final paired refresh: **four visual
comparisons and 138 archived reports** at this checkpoint.

## Build and refresh

From `codebase/agentdojo-lab`, use the Python 3.12 lab environment:

```bash
.venv/bin/python scripts/build_visual_report_library.py --build
```

This writes:

- `reports/visual-library-v1/index.html`: the searchable offline catalog.
- `reports/visual-library-v1/inventory.json`: source HTML hashes, run input
  hashes, visual output paths, record counts, export errors, and limitations.
- `reports/visual-library-v1/runs/<lab-relative-run-path>/report.html`: visual
  single-run copies. For example, the source `runs/scout-case-a-prepared-v5/clean`
  maps to `reports/visual-library-v1/runs/runs/scout-case-a-prepared-v5/clean/report.html`.

Paired pages generated separately under
`reports/visual-library-v1/paired/**/index.html` are discovered automatically.
The current Case A feature opens `paired/case-a/index.html` when available and
otherwise opens the original Case A paired-report route.

Rebuild paired views from saved comparison records after rebuilding single runs:

```bash
.venv/bin/python scripts/refresh_visual_pair_reports.py --update-current
```

The updater discovers saved `runs/*/paired-report/pair.json` and report fixture
comparisons using the supported protocol. This checkpoint creates four pages:

- `paired/case-a/index.html`: the saved Scout Case A comparison.
- `paired/scout-case-a-prepared-v6/index.html`: the additional saved Case A pair
  that appeared during the reporting snapshot.
- `paired/20260915-paired-report-fixture-v1/index.html`: the first offline fixture.
- `paired/20260915-paired-report-fixture-v2/index.html`: the second offline fixture.

The optional `--update-current` flag also refreshes the user-requested existing
route, `runs/scout-case-a-prepared-v5/paired-report/index.html`. Before replacement,
the updater preserves its original bytes under the library's
`original-pages/case-a-paired-<SHA256>.html`. Run HTML, raw inputs, and original
`pair.json` bytes remain unchanged. Omit the flag to update only versioned copies.
`paired-refresh.json` records input verification, new views, and the backup path.

The historical `reports/20260908-canary-pair-v1/pair.json` uses a different
comparison protocol and is explicitly skipped by this updater. Its original
report remains an archived report; it is not relabeled as a clean/attacked pair.

After adding paired reports, refresh catalog links without exporting runs again:

```bash
.venv/bin/python scripts/build_visual_report_library.py --catalog-only
```

The catalog uses the paired refresh receipt to associate each new paired view
with its original report. Run titles identify the family and condition rather
than repeating a generic HTML template title.

Both `build_visual_report_library.py` modes accept `--lab PATH` and `--output PATH`.
The paired updater accepts `--library PATH` and the optional `--update-current` flag.
The library-builder output must be a
dedicated directory below the selected lab's `reports/` directory. The builder
excludes its own output from source discovery and never traverses frozen-runtime
directories or directory symlinks.

## Evidence preservation

The library builder does not modify the source run's HTML, JSON, JSONL, or other
evidence files. It checks all inventoried original HTML hashes and the run
exporter's input hashes after generation; an observed source change fails the
build. It uses existing evidence only and issues no model, network, scheduler,
or simulated-tool requests.

Some frozen inventories include the original `report.html` hash. Keep versioned
visual copies separate from these source files. Do not overwrite historical
analyses or regenerate their original evidence manifests to accommodate a new
presentation. Any separately authorized in-place presentation update must retain
its original bytes and document its scope independently of this builder.

Charts describe observable events and recorded order. Source exposure, content
correspondence, predicted influence, observed interventions, and executed sink
outcomes must retain their separate meanings. Every generated artifact and this
repository's documentation use English.

## Browser verification

`scripts/check_visual_reports.cjs` checks the requested Case A route, source links,
event 34/37 differences, single-run SVG selection and desktop/phone layouts in
Chromium. It writes `browser-verification.json` and PNG previews to the library.
Playwright is an optional development dependency and is not loaded by any HTML.
For an external installation, set `PLAYWRIGHT_MODULE` to its module directory and
`PLAYWRIGHT_BROWSERS_PATH` to its browser cache, then run the script with Node.
