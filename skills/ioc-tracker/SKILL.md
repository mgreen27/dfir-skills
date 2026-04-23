---
name: ioc-tracker
description: Maintain a cross-host IOC and adversary-tracking view across investigations. Use when analysis on one machine surfaces indicators that should be compared against other hosts or preserved for later VT/TI enrichment.
---

# IOC Tracker

Use this skill to keep a shared, cross-host indicator record inside the active
investigation case folder.

## Purpose

This skill is for indicators that matter across more than one host:

- atomic indicators such as filenames, file paths, usernames, task names,
  command lines, process names, parent-child chains, registry paths, services,
  network artifacts, and hashes
- tracking indicators that help follow an adversary across hosts even when a
  single atomic IOC is weak on its own

## Workflow

1. Review the current investigation `wiki/` and raw outputs first.
2. Promote only useful cross-host indicators into the investigation tracker.
3. Separate `Atomic Indicators` from `Tracking Indicators`.
4. For each indicator, capture:
   - value
   - type
   - source host
   - source artifact
   - confidence
   - why it matters
   - follow-up status
   - TI status, including whether it was enriched, skipped as internal, or is
     unsupported as a native VT object type
5. Update `wiki/analysis.md` with the behaviors or TTP patterns that matter
   across machines.
6. Link the relevant case wiki pages back to the tracked indicators when the
   overlap is meaningful.

## Files

- `./investigations/<investigation_id>/spreadsheet-of-doom/host-indicators.csv`
- `./investigations/<investigation_id>/spreadsheet-of-doom/network-indicators.csv`
- `./investigations/<investigation_id>/spreadsheet-of-doom/systems.csv`
- `./investigations/<investigation_id>/wiki/analysis.md`

## Guidance

- `Atomic Indicators`
  Use for exact filenames, file paths, hashes, task names, command lines,
  services, registry paths, domains, IPs, and usernames.
- `Tracking Indicators`
  Use for patterns such as `services.exe -> suspicious binary`,
  `WmiPrvSE.exe -> ntdsutil.exe`, `wsmprovhost.exe` remote PowerShell context,
  VSS staging behavior, staging directory conventions, or user/operator
  behaviors that help tie multiple hosts to the same intrusion.

## Notes

- Keep the case tracker concise and evidence-backed.
- Mark weak indicators as weak; do not overclaim.
- When VirusTotal is available, enrich hashes, domains, URLs, and public IPs.
- Skip internal domains and private IPs by default and say that explicitly in
  the `TI Status` field.
- If an indicator is not a native VT object type, mark it unsupported instead
  of leaving `TI Status` vague.
