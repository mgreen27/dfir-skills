---
name: windows-execution-analysis
description: Collect or reuse Velociraptor evidence-of-execution artifacts for Windows clients in an investigation and save curated raw outputs plus a manifest under the case evidence tree. Use when you want a repeatable execution-evidence sweep across one or more mapped or live Windows clients.
---

# Windows Execution Analysis

Use this skill to run the core Windows evidence-of-execution artifact set
through the local Velociraptor API and save the results in a dedicated
execution-analysis folder per system.

The curated artifact set is:

- `Windows.Detection.Amcache`
- `Windows.Forensics.Bam`
- `Windows.Forensics.Timeline`
- `Windows.Registry.UserAssist`
- `Windows.Registry.AppCompatCache`
- `Windows.System.AppCompatPCA`
- `Windows.Forensics.Prefetch`

## Workflow

1. Confirm the repo-local Velociraptor workspace exists under `./velociraptor`.
2. Confirm the target clients are online and have a recent `LastSeen`.
3. Reuse finished flows where possible instead of queueing duplicates.
4. Queue missing artifacts only when no reusable finished flow exists.
5. Save the raw results under:
   `./investigations/<investigation_id>/evidence/systems/<system>/velociraptor/execution-analysis/`
6. Save a per-host manifest as TSV so later AI review does not have to reopen
   every raw JSONL file immediately.
7. Run `investigation-ingest` after the collection wave so the case `wiki/`
   reflects the refreshed evidence set.

## Commands

Run the full execution-evidence sweep for the current case systems:

```bash
cd /Users/matt/git/dfir-skills
./venv/bin/python ./skills/windows-execution-analysis/scripts/run_windows_execution_analysis.py \
  --investigation-id shieldbase-intrusion \
  --host base-dc \
  --host base-file
```

Rerun and force fresh collections instead of reusing finished flows:

```bash
cd /Users/matt/git/dfir-skills
./venv/bin/python ./skills/windows-execution-analysis/scripts/run_windows_execution_analysis.py \
  --investigation-id shieldbase-intrusion \
  --host base-dc \
  --rerun
```

Sync the investigation after the outputs land:

```bash
cd /Users/matt/git/dfir-skills
./skills/investigation-ingest/scripts/sync_investigation.sh shieldbase-intrusion
```

## Notes

- This skill is intentionally focused on execution evidence, not broader
  persistence or registry hunting.
- `Windows.Forensics.Bam`, `Windows.Forensics.Prefetch`, and
  `Windows.System.AppCompatPCA` may return sparse or empty results depending on
  the underlying image and Windows version.
- Keep the raw artifact outputs as `.jsonl` and use the generated
  `execution-analysis-manifest.tsv` for quick review.
