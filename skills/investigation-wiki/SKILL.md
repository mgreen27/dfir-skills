---
name: investigation-wiki
description: Scaffold a per-host Obsidian investigation vault for iterative DFIR analysis. Use when you need to create a case wiki, initialize a machine-specific analysis vault, or establish the durable note structure that sits beside raw DFIR outputs.
---

# Investigation Wiki

Use this skill when a host needs its own Obsidian vault for iterative DFIR
analysis.

The vault is the durable analyst workspace. Raw tool outputs stay under
`./investigations/<hostname>/`, while the vault under
`./investigation-wikis/<hostname>/` holds the evolving narrative, leads,
timeline, and artifact-review notes.

## Workflow

1. Determine the host or investigation name.
2. Keep raw outputs in `./investigations/<hostname>/`.
3. Create or reuse the vault in `./investigation-wikis/<hostname>/`.
4. Use the scaffold script to create the standard DFIR wiki layout.
5. Treat `wiki/findings.md`, `wiki/timeline.md`, `wiki/leads.md`, and
   `wiki/evidence.md` as the core iterative-analysis pages.
6. Refresh `wiki/hot.md` and `wiki/log.md` after meaningful changes.
7. If an older case used `investigation-notes.md` or
   `investigation-results.md`, migrate those into the vault and stop using the
   flat markdown files as the system of record.

## Standard Layout

```text
investigation-wikis/<hostname>/
  AGENTS.md
  evidence -> ../../investigations/<hostname>
  wiki/
    index.md
    hot.md
    log.md
    overview.md
    findings.md
    timeline.md
    leads.md
    evidence.md
    artifacts/
      _index.md
    questions/
      _index.md
    meta/
      sync-status.md
```

## Commands

Create the vault for a host:

```bash
/Users/matt/git/dfir-skills/skills/investigation-wiki/scripts/init_investigation_wiki.sh base-dc
```

Create the vault for a host with an explicit investigation directory:

```bash
/Users/matt/git/dfir-skills/skills/investigation-wiki/scripts/init_investigation_wiki.sh \
  base-dc \
  /Users/matt/git/dfir-skills/investigations/base-dc
```

## Notes

- The generated `evidence` symlink points the vault at the raw result folder so
  Obsidian can browse the underlying case outputs.
- Keep long-form reasoning and evolving conclusions in the wiki pages, not in
  the raw result directory.
- Use the ingest skill after new Velociraptor or Volatility results land so the
  artifact index stays current.
