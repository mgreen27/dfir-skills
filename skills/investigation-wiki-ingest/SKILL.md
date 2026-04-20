---
name: investigation-wiki-ingest
description: Sync raw DFIR outputs into a per-host Obsidian investigation vault for iterative analysis. Use when new Velociraptor or Volatility results have landed, when you need file-level artifact notes, or when a legacy flat investigation should be migrated into the case wiki.
---

# Investigation Wiki Ingest

Use this skill after new raw outputs are written under
`./investigations/<hostname>/`.

This skill does not reinterpret every artifact. It keeps the case wiki current
so iterative analysis has a reliable artifact index, refreshed hot cache, and a
place to migrate older flat notes into the vault.

## Workflow

1. Confirm the raw output directory exists under `./investigations/<hostname>/`.
2. Create the case vault first if it does not already exist.
3. Sync the case outputs into generated artifact notes under
   `wiki/artifacts/`.
4. Refresh `wiki/evidence.md`, `wiki/hot.md`, `wiki/log.md`, and
   `wiki/meta/sync-status.md`.
5. If `investigation-notes.md` or `investigation-results.md` still exist in the
   raw result folder, migrate them into `wiki/meta/legacy-flat-notes.md` and
   `wiki/meta/legacy-flat-results.md`, then stop treating the flat files as the
   case record.

## Commands

Sync the default host case:

```bash
/Users/matt/git/dfir-skills/skills/investigation-wiki-ingest/scripts/sync_investigation_wiki.sh base-dc
```

Sync a case with explicit locations:

```bash
/Users/matt/git/dfir-skills/skills/investigation-wiki-ingest/scripts/sync_investigation_wiki.sh \
  base-dc \
  /Users/matt/git/dfir-skills/investigations/base-dc \
  /Users/matt/git/dfir-skills/investigation-wikis/base-dc
```

## Notes

- The generated artifact notes are inventory pages. Put analyst judgement in
  `wiki/findings.md`, `wiki/leads.md`, and `wiki/timeline.md`.
- Re-run this sync after each major collection wave so the vault reflects the
  latest case material.
