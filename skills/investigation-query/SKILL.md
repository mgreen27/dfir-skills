---
name: investigation-query
description: Query an investigation-centric case wiki and Spreadsheet of Doom without rereading every raw artifact. Use when you need to answer case questions from the investigation record, review the latest leads, or synthesize prior analysis from the iterative DFIR notes.
---

# Investigation Wiki Query

Use this skill to answer case questions from an investigation-centric case
wiki and its Spreadsheet of Doom.

The point is to use the accumulated analysis, not to re-open every raw file on
every turn.

## Query Modes

| Mode | Use when | Read budget |
|---|---|---|
| Quick | current status, latest lead, current verdict | `wiki/hot.md`, `wiki/analysis.md` |
| Standard | most case questions | hot cache, analysis, investigative questions, spreadsheet note, evidence |
| Deep | broad synthesis or contradiction review | relevant wiki pages, Spreadsheet of Doom CSVs, plus selected raw outputs |

## Workflow

1. Read `wiki/hot.md` first.
2. Read `wiki/index.md` only if the hot cache is not enough.
3. For status questions, prioritize `wiki/analysis.md`,
   `wiki/investigative-questions.md`, and the Spreadsheet of Doom note.
4. For chronology questions, read `../spreadsheet-of-doom/timeline.csv`
   before reopening raw files.
5. For host inventory or system-scoping questions, read
   `../spreadsheet-of-doom/systems.csv`.
6. For source-path or output-location questions, read `wiki/evidence.md` and
   `wiki/artifacts/_index.md`.
7. Only open raw files from the `evidence/` directory when the wiki and
   Spreadsheet of Doom do not already contain enough support.
8. If the investigation record surfaces an unresolved question, decide whether
   that question is best answered by more Velociraptor disk collection or more
   Volatility memory collection.
9. Run the relevant collection workflow, save the raw outputs under
   `./investigations/<investigation_id>/`, update the appropriate Spreadsheet
   of Doom CSV, and sync the wiki before answering.
10. If the answer is durable, write it back into `wiki/questions/` or update
   `wiki/analysis.md`.

## Notes

- Prefer exact citations to wiki pages and raw output paths.
- If the wiki is stale, run the ingest skill before answering deep questions.
- The wiki-query skill is allowed to trigger more collection when the wiki
  contains a clear open question that cannot be answered from current evidence.
- The Spreadsheet of Doom should guide which host, artifact, indicator, or task
  gets reviewed next when multiple leads compete for attention.
