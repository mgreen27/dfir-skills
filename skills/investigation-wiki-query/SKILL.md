---
name: investigation-wiki-query
description: Query a per-host Obsidian investigation vault without rereading every raw artifact. Use when you need to answer case questions from the host wiki, review the latest leads, or synthesize prior analysis from the iterative DFIR notes.
---

# Investigation Wiki Query

Use this skill to answer case questions from a host's Obsidian investigation
vault.

The point is to use the accumulated analysis, not to re-open every raw file on
every turn.

## Query Modes

| Mode | Use when | Read budget |
|---|---|---|
| Quick | current status, latest lead, current verdict | `wiki/hot.md`, `wiki/findings.md` |
| Standard | most case questions | hot cache, findings, leads, timeline, evidence |
| Deep | broad synthesis or contradiction review | all relevant wiki pages plus selected raw outputs |

## Workflow

1. Read `wiki/hot.md` first.
2. Read `wiki/index.md` only if the hot cache is not enough.
3. For status questions, prioritize `wiki/findings.md` and `wiki/leads.md`.
4. For chronology questions, read `wiki/timeline.md`.
5. For source-path or output-location questions, read `wiki/evidence.md` and
   `wiki/artifacts/_index.md`.
6. Only open raw files from the `evidence` symlink when the wiki does not
   already contain enough support.
7. If the answer is durable, write it back into `wiki/questions/` or update the
   relevant core page.

## Notes

- Prefer exact citations to wiki pages and raw output paths.
- If the wiki is stale, run the ingest skill before answering deep questions.
