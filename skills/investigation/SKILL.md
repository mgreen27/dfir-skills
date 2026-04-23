---
name: investigation
description: Scaffold an investigation-centric case folder plus Spreadsheet of Doom CSVs for iterative DFIR analysis. Use when you need a durable case wiki, an investigation-wide structured workbook layout, or a shared case record that spans multiple systems.
---

# Investigation Wiki

Use this skill when an investigation needs its own case folder, markdown wiki,
and Spreadsheet of Doom.

Raw outputs should be organized under `./investigations/<investigation_id>/`,
with per-system data under `evidence/systems/<system>/`, the investigation-wide
Spreadsheet of Doom under `spreadsheet-of-doom/`, and narrative analysis under
`wiki/`.

## Workflow

1. Determine the investigation id.
2. Keep raw outputs in
   `./investigations/<investigation_id>/evidence/systems/<system>/`.
3. Create or reuse the case folder in `./investigations/<investigation_id>/`.
4. Use the scaffold script to create sibling `wiki/`,
   `spreadsheet-of-doom/`, and `evidence/` folders under the investigation
   root.
5. Treat the Spreadsheet of Doom CSVs as the canonical structured case record.
6. Generate or refresh the root-level workbook export
   `<investigation_id>_SoD.xlsx` after each meaningful update.
7. Use `wiki/analysis.md`, `wiki/investigative-questions.md`,
   `wiki/spreadsheet-of-doom.md`, `wiki/evidence.md`, `wiki/hot.md`, and
   `wiki/log.md` as the core narrative and coordination pages.
8. Refresh `wiki/hot.md` and `wiki/log.md` after meaningful changes.
9. Keep the case-level `AGENTS.md` aligned with the repo prompt so the case
   workflow can both write analysis into the wiki and trigger follow-up
   collection from open questions in the wiki and Spreadsheet of Doom.

## Standard Layout

```text
investigations/<investigation_id>/
  AGENTS.md
  evidence/
    systems/
      <system>/
        velociraptor/
        volatility3/
    virustotal/
  spreadsheet-of-doom/
    timeline.csv
    systems.csv
    users.csv
    host-indicators.csv
    network-indicators.csv
    task-tracker.csv
    evidence-tracker.csv
    keywords.csv
  <investigation_id>_SoD.xlsx
  wiki/
    index.md
    hot.md
    log.md
    analysis.md
    spreadsheet-of-doom.md
    investigative-questions.md
    evidence.md
    artifacts/
      _index.md
    questions/
      _index.md
    meta/
      sync-status.md
```

## Commands

Create the case folder for an investigation:

```bash
./skills/investigation/scripts/init_investigation.sh shieldbase-intrusion
```

Create the case folder with an explicit investigation path:

```bash
./skills/investigation/scripts/init_investigation.sh \
  shieldbase-intrusion \
  ./investigations/shieldbase-intrusion
```

## Notes

- The generated investigation root has sibling `wiki/`, `spreadsheet-of-doom/`,
  and `evidence/` folders so the structured case record sits beside the raw
  evidence view.
- Keep structured facts in the Spreadsheet of Doom CSVs and keep short
  narrative reasoning in the wiki pages.
- Refresh the workbook export after updating the CSVs so analysts have a quick
  XLSX view without changing the canonical CSV record.
- Use `task-tracker.csv` and the analysis page to route open leads and next
  actions.
- Use the case `AGENTS.md` to make the iterative loop explicit: the wiki is
  allowed to drive more Velociraptor or Volatility collection when it exposes
  a clear open question.
- Use the ingest skill after new Velociraptor or Volatility results land so the
  artifact index and Spreadsheet of Doom links stay current.
