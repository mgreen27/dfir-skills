---
name: windows-timeline
description: Run bounded post-analysis Windows timeline pivots by querying Windows.NTFS.MFT and Windows.EventLogs.EvtxHunter with shared time bounds and optional IOC/path filters. Use when iterative analysis has narrowed the interesting window and you want to hunt for adjacent file and event-log activity without rerunning the full baseline collection.
---

# Windows Timeline

Use this skill after iterative analysis, not before it.

The goal is to take a suspicious window that already emerged from EVTX,
Registry Hunter, Prefetch, Amcache, Volatility, or wiki analysis, and then run
a bounded adjacent-activity pivot across:

- `Windows.NTFS.MFT`
- `Windows.EventLogs.EvtxHunter`

This skill reuses the `windows-collection` engine so it inherits prior-flow
reuse checks, polling, export, and investigation-tree output handling.

## Workflow

1. Read `wiki/hot.md`, `wiki/analysis.md`, and `spreadsheet-of-doom/timeline.csv`
   first.
2. Identify the exact time window you want to inspect.
3. Prefer UTC `DateAfter` and `DateBefore` bounds.
4. Add path, file, event id, channel, provider, or IOC regex filters when you
   already know what kind of activity you are trying to widen or confirm.
5. Queue or reuse the bounded timeline collection.
6. Review the saved CSV exports under the host `velociraptor/exports/` tree.
7. Promote confirmed events into `timeline.csv`, indicators into the relevant
   Spreadsheet of Doom sheets, and analyst judgement into `wiki/analysis.md`.
8. Re-run investigation ingest so the case folder reflects the new raw outputs.

## Commands

Run a bounded MFT+EVTX pivot:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  ensure \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --collection-type timeline \
  --date-after 2026-05-01T00:00:00Z \
  --date-before 2026-05-01T06:00:00Z
```

Run a tighter timeline hunt with adjacent-activity filters:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  ensure \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --collection-type timeline \
  --date-after 2026-05-01T00:00:00Z \
  --date-before 2026-05-01T06:00:00Z \
  --mft-path-regex 'C:\\Windows\\Temp\\|C:\\Users\\.*\\AppData\\' \
  --mft-file-regex '.*\\.(exe|dll|ps1|bat|cmd|zip)$' \
  --evtx-ioc-regex 'powershell|cmd\\.exe|rundll32|wmic|schtasks' \
  --evtx-channel-regex 'Security|System|Microsoft-Windows-PowerShell/Operational'
```

Check whether the same bounded pivot already exists:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  check \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --collection-type timeline \
  --date-after 2026-05-01T00:00:00Z \
  --date-before 2026-05-01T06:00:00Z
```

Refresh the case folder after the exports land:

```bash
./skills/investigation-ingest/scripts/sync_investigation.sh shieldbase-intrusion
```

## Notes

- The exact artifact name is `Windows.EventLogs.EvtxHunter`.
- At least one time bound is required for the timeline collection type. In
  practice, use both bounds whenever possible.
- The default EVTX regex is `.` for bounded broad review. Narrow it when you
  already have a lead, otherwise the result volume can still be large.
- The default MFT filters are `MFTDrive=C:`, `PathRegex=.`, and
  `FileRegex=.`, so add tighter filters when the time window is still busy.
- Env-bound exports and manifests now carry stable suffixes derived from the
  request shape, so repeated timeline pivots remain durable instead of
  overwriting earlier bounded hunts.
