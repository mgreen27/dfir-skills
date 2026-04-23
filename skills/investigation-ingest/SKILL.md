---
name: investigation-ingest
description: Sync raw DFIR outputs into an investigation-centric case folder and refresh Spreadsheet of Doom links. Use when new Velociraptor or Volatility results have landed or when you need file-level artifact notes for the active investigation record.
---

# Investigation Wiki Ingest

Use this skill after new raw outputs are written under
`./investigations/<investigation_id>/`.

This skill does not reinterpret every artifact. It keeps the case wiki current
so iterative analysis has a reliable artifact index, refreshed hot cache,
up-to-date Spreadsheet of Doom links, and a root-level XLSX export.

## Workflow

1. Confirm the raw output directory exists under
   `./investigations/<investigation_id>/`.
2. Create the case folder first if it does not already exist.
3. Sync the case outputs into generated artifact notes under
   `wiki/artifacts/`.
4. Refresh `wiki/evidence.md`, `wiki/spreadsheet-of-doom.md`, `wiki/hot.md`,
   `wiki/log.md`, and `wiki/meta/sync-status.md`.
5. Export `<investigation_id>_SoD.xlsx` in the investigation root.
6. Keep the active investigation folder aligned with the current Spreadsheet of
   Doom and raw evidence layout.

## Commands

Sync the default investigation case:

```bash
/Users/matt/git/dfir-skills/skills/investigation-ingest/scripts/sync_investigation.sh shieldbase-intrusion
```

Sync a case with an explicit investigation path:

```bash
/Users/matt/git/dfir-skills/skills/investigation-ingest/scripts/sync_investigation.sh \
  shieldbase-intrusion \
  /Users/matt/git/dfir-skills/investigations/shieldbase-intrusion
```

## Notes

- The generated artifact notes are inventory pages. Put structured case facts
  in the Spreadsheet of Doom CSVs and short analyst judgement in
  `wiki/analysis.md`.
- Update the CSV sheets first, then refresh the XLSX export from those CSVs.
- Re-run this sync after each major collection wave so the case folder reflects
  the latest case material.
- The sync only inventories files from `evidence/` and `spreadsheet-of-doom/`
  so it does not recursively ingest generated wiki pages.
