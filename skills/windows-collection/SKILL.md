---
name: windows-collection
description: Queue Windows-focused Velociraptor collection flows for the repo's dead-disk or offline mapped-client workflow, track their status, and automatically export finished results to CSV. Use when you want repeatable offline collection plus ready-to-review host exports under the investigation tree.
---

# Windows Collection

Use this skill when the goal is to start a repeatable Windows collection wave
for dead-disk or offline mapped-client analysis, track it to completion, and
save generic CSV exports for finished artifacts. This skill does not do
analyst interpretation. Once exports exist, analysis should prefer reviewing
those exported rows over starting new collection unless recollection is
explicitly requested or the exports cannot answer the evidence question.

## Workflow

1. Confirm the repo-local Velociraptor workspace exists under `./velociraptor`.
2. Confirm the target is the local mapped dead-disk or offline client you intend to collect from.
3. Confirm the target client is online and has a recent `LastSeen`.
4. Resolve the target collection type or explicit artifact into individual artifacts.
5. Check whether each artifact already has a matching prior flow with the
   expected arguments.
6. Reuse matching finished or in-flight flows artifact-by-artifact.
7. Queue a new Velociraptor flow per missing artifact, or queue fresh flows for
   all requested artifacts when you explicitly force a rerun.
8. Save the per-artifact flow map under the investigation evidence tree.
9. Poll the saved per-artifact flow state until the requested set is finished.
10. Automatically export finished flows to CSV under the host
   `velociraptor/exports/` tree unless you explicitly disable export.
11. Treat those exports as the default handoff for later analyst review and
    avoid recollecting the same evidence unless you explicitly need a rerun or
    a missing artifact scope.

The helper uses the repo-local `pyvelociraptor` client and bundled `.vql`
files under `references/` instead of shelling out to `velociraptor query`.
For a remote live Velociraptor environment, use the separate
`windows-collection-live` skill.

## Bulk Host Collection Helper

Run from the repo root. `queue` and `ensure` now poll by default after they
save the per-artifact state, then automatically export CSVs when the requested
set is complete. The normal process is "queue or ensure, wait for completion,
and get exports in the same command."

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  queue \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --collection-type all
```

Queue only the execution-focused subset:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  queue \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --collection-type execution
```

Run a bounded post-analysis timeline pivot across MFT and EVTX:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  ensure \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --collection-type timeline \
  --date-after 2026-05-01T00:00:00Z \
  --date-before 2026-05-01T06:00:00Z \
  --mft-path-regex 'C:\\Windows\\Temp\\|C:\\Users\\.*\\AppData\\' \
  --evtx-ioc-regex 'powershell|cmd\\.exe|rundll32|wmic'
```

Queue the default full set without spelling out a type:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  queue \
  --investigation-id shieldbase-intrusion \
  --host base-file
```

Queue one new flow per artifact but return immediately after the flows are
saved:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  queue \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --no-poll
```

Queue one new flow per artifact and skip the automatic CSV export:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  queue \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --no-export
```

Check the saved flow status later:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  status \
  --investigation-id shieldbase-intrusion \
  --host base-file
```

Export the full baseline collection into generic CSVs:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  export \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --collection-type all
```

Export one specific artifact with the same explicit variables you used during
collection:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  export \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --artifact Windows.Search.FileFinder \
  --env Glob='C:\\Windows\\Temp\\*.exe'
```

Export curated `Windows.Registry.Hunter` Program Execution views:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  export-registry-hunter \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --profile execution
```

Poll until the saved collection set is complete:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  poll \
  --investigation-id shieldbase-intrusion \
  --host base-file
```

Poll until the saved collection set is complete but skip the automatic CSV
export:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  poll \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --no-export
```

Check whether the full baseline collection already exists with the expected
request shape:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  check \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --collection-type all
```

Check whether the execution collection type already exists with the expected
request shape:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  check \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --collection-type execution
```

Ensure one custom artifact exists with explicit variables:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  ensure \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --artifact Windows.Search.FileFinder \
  --env Glob='C:\\Windows\\Temp\\*.exe'
```

Ensure the execution collection type exists, queueing only the missing artifact
flows, then polling until the saved set is complete:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  ensure \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --collection-type execution
```

Force a fresh execution rerun with one new flow per artifact:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  ensure \
  --investigation-id shieldbase-intrusion \
  --host base-file \
  --collection-type execution \
  --force-run
```

## Named Collection Types

`all` expands to the full baseline Windows set:

- `triage`
- `execution`
- `persistence`
- `lateral-movement`
- `registry`

`execution` expands only to the focused evidence-of-execution subset:

- `Windows.Detection.Amcache`
- `Windows.Forensics.Bam`
- `Windows.Forensics.RecentFileCache`
- `Windows.Forensics.Timeline`
- `Windows.Forensics.SRUM`
- `Windows.System.AppCompatPCA`
- `Windows.Forensics.Prefetch`
- `Windows.Registry.Hunter[all]`

`persistence` expands to the persistence-focused subset:

- `Windows.Sys.StartupItems`
- `Windows.System.Services`
- `Windows.System.TaskScheduler`
- `Windows.Registry.TaskCache.HiddenTasks`
- `Windows.Registry.Hunter[all]`
- `Windows.Persistence.PermanentWMIEvents`
- `Windows.Sysinternals.Autoruns`

`lateral-movement` expands to the remote access and movement-focused subset:

- `Windows.Detection.PublicIP`
- `Windows.EventLogs.RDPAuth`
- `Windows.EventLogs.ExplicitLogon`
- `Windows.Registry.MountPoints2`
- `Windows.EventLogs.ServiceCreationComspec`

`timeline` expands to a bounded post-analysis pivot set:

- `Windows.NTFS.MFT`
- `Windows.EventLogs.EvtxHunter`

Use `timeline` only after iterative analysis has already narrowed the
interesting time window. Pass `--date-after`, `--date-before`, or both so the
same bounds are applied to both artifacts, and add optional MFT or EVTX regex
filters when you want a tighter hunt.

The full `all` set resolves to:

- `DetectRaptor.Windows.Detection.Evtx`
- `DetectRaptor.Windows.Detection.Applications`
- `DetectRaptor.Windows.Detection.Powershell.PSReadline`
- `DetectRaptor.Windows.Detection.MFT`
- `DetectRaptor.Windows.Detection.ZoneIdentifier`
- `Windows.Detection.Amcache`
- `Windows.Forensics.Bam`
- `Windows.Forensics.RecentFileCache`
- `Windows.Forensics.Timeline`
- `Windows.Forensics.SRUM`
- `Windows.System.AppCompatPCA`
- `Windows.Forensics.Prefetch`
- `Windows.Sys.StartupItems`
- `Windows.System.Services`
- `Windows.System.TaskScheduler`
- `Windows.Registry.TaskCache.HiddenTasks`
- `Windows.Persistence.PermanentWMIEvents`
- `Windows.Sysinternals.Autoruns`
- `Windows.Detection.PublicIP`
- `Windows.EventLogs.RDPAuth`
- `Windows.EventLogs.ExplicitLogon`
- `Windows.Registry.MountPoints2`
- `Windows.EventLogs.ServiceCreationComspec`
- `Windows.Registry.Hunter[all]`

## Outputs

The helper writes collection metadata under:

```text
./investigations/<investigation_id>/evidence/systems/<system>/velociraptor/host-collection/
```

Important files:

- `host-collection-state.json`
- `requests/<request_id>/state.json`
- one `<system>-<artifact>-queue.json` file per freshly queued artifact

CSV exports land under:

```text
./investigations/<investigation_id>/evidence/systems/<system>/velociraptor/exports/
```

The request-scoped state file is the handoff point for later analysis-side
download work. It tracks the target collection type, requested artifacts,
expected argument signatures, and the per-artifact `artifact -> flow_id`
mapping used for later CSV export. `host-collection-state.json` remains as the
latest-state compatibility pointer for the host, but long-running casework
should prefer the request-specific state under `requests/<request_id>/`.
In normal casework, later review should start from the exported CSVs before
considering more collection.

## Notes

- The skill now queues one Velociraptor flow per artifact so later export logic
  can save one CSV per relevant result component.
- `queue` and `ensure` now poll by default after they write the saved
  per-artifact state. Use `--no-poll` when you explicitly want to queue or
  reuse flows and return immediately.
- `queue`, `ensure`, and `poll` now export finished collection results to CSV
  by default after the requested set is complete. Use `--no-export` when you
  explicitly want to skip that step.
- `--artifact` lets you request a specific artifact outside the named
  collection types.
- `--env KEY=VALUE` is available for one explicit `--artifact` target when you
  need to collect that artifact with custom variables. The same explicit
  artifact can be combined with `--collection-type all` or
  `--collection-type execution` if you need the baseline set plus one
  parameterized follow-up artifact.
- `--collection-type timeline` is a bounded post-analysis pivot that runs
  `Windows.NTFS.MFT` and `Windows.EventLogs.EvtxHunter` together with the same
  `DateAfter` and `DateBefore` window. It is for adjacent-activity review
  after iterative analysis identifies a suspicious time span, not for the
  default broad first-pass collection.
- `poll` remains available as an explicit follow-up when you want to wait on an
  already-saved collection set. It repeatedly refreshes the saved per-artifact
  state until all requested flows are out of open states, or until the poll
  timeout is reached.
- `status`, `poll`, and `export` accept `--request-id` when you want to work
  from a specific prior collection state instead of whatever the host's latest
  `host-collection-state.json` happens to point at.
- The default collection set intentionally omits `Windows.Registry.UserAssist`
  and `Windows.Registry.AppCompatCache`; collect those through
  `Windows.Registry.Hunter` when you want registry-backed coverage instead of
  separate lightweight artifacts.
- The persistence set now includes `Windows.System.Services`,
  `Windows.Persistence.PermanentWMIEvents`, and
  `Windows.Sysinternals.Autoruns`, but the last two are still expected to be
  weak or non-functional on mapped dead-disk clients. Treat empty output there
  as a collection-mode caveat before you treat it as absence of evidence.
- `Windows.Registry.Hunter` is now treated as a core collection artifact. The
  collection layer always normalizes registry-section requests to a single
  `Windows.Registry.Hunter[all]` flow with `RemappingStrategy='None'`, and
  later export work should slice that broad result set into execution,
  system-info, ASEP, or other category-specific CSVs.
- `Windows.Registry.Hunter[all]` now queues with a collection-level timeout of
  `1800` seconds. In this workflow, that timeout must be passed to
  `collect_client(..., timeout=...)`; the spec-local `timeout` field is not a
  reliable match key for reused flows.
- `check` and `ensure` match prior flows per artifact by requested artifact
  specs, not just by the flow ids saved from earlier runs of this skill, so
  prior hunt-driven or manually queued collections can be reused.
- `--force-run` bypasses that reuse logic and queues a fresh collection when
  you explicitly want a rerun.
- `export` writes one generic `<ArtifactName>_full.csv` file per non-registry
  artifact.
- `Windows.NTFS.MFT` is exported through a fixed projected schema instead of a
  raw `SELECT *` dump. The CSV keeps:
  `EntryNumber`, `ParentEntryNumber`, `InUse`, `OSPath`, `FileSize`,
  `Created0x10`, `Created0x30`, `LastModified0x10`, `LastModified0x30`,
  `LastRecordChange0x10`, `LastRecordChange0x30`, `LastAccess0x10`, and
  `LastAccess0x30`.
- `Windows.EventLogs.EvtxHunter` is also exported through a fixed projected
  schema instead of a raw `SELECT *` dump. The CSV keeps: `EventTime`,
  `Provider`, `EventID`, `EventRecordID`, `UserSID`, `Username`, `EventData`,
  and `UserData`.
- `Windows.EventLogs.RDPAuth` is exported through a fixed projected schema.
  The CSV keeps: `EventTime`, `Channel`, `EventID`, `DomainName`, `UserName`,
  `LogonType`, `SourceIP`, `Description`, and `EventRecordID`.
- `Windows.EventLogs.ExplicitLogon` is exported through a fixed projected
  schema. The CSV keeps: `EventTime`, `EventID`, `EventRecordID`,
  `SubjectUserName`, `SubjectDomainName`, `TargetUserName`,
  `TargetDomainName`, `TargetServerName`, `ProcessName`, `EventData`, and
  `Message`.
- Env-bound exports now carry a stable suffix derived from the request
  arguments so repeated timeline pivots or targeted follow-up runs do not
  overwrite earlier CSVs or manifests.
- Automatic export after `queue`, `ensure`, or `poll` uses the same generic
  CSV logic as the explicit `export` command. Use the explicit export
  subcommands again later when you want to re-export a finished set or run a
  curated `Windows.Registry.Hunter` profile.
- `Windows.Forensics.SRUM` is exported as four scope-specific CSVs:
  `Windows.Forensics.SRUM.Execution Stats.csv`,
  `Windows.Forensics.SRUM.Application Resource Usage.csv`,
  `Windows.Forensics.SRUM.Network Connections.csv`, and
  `Windows.Forensics.SRUM.Network Usage.csv`.
- `export` handles `Windows.Registry.Hunter` specially by reading
  `Windows.Registry.Hunter/Results` and writing one CSV per `Category`, for
  example `Windows.Registry.Hunter.asep.csv` or
  `Windows.Registry.Hunter.program-execution.csv`.
- `export-registry-hunter --profile execution` runs curated `.vql` views for
  Program Execution and writes:
  `Windows.Registry.Hunter.Execution.AppCompatCache.csv`,
  `Windows.Registry.Hunter.Execution.UserAssist.csv`,
  `Windows.Registry.Hunter.Execution.RADAR.csv`, and
  `Windows.Registry.Hunter.Execution.BAM.csv`.
- `export-registry-hunter --profile system-info` writes the flow-scoped
  `Windows.Registry.Hunter.SystemInfo.csv` view from the `System Info`
  category.
- `export-registry-hunter --profile web-browsers` writes the flow-scoped
  `Windows.Registry.Hunter.WebBrowsers.csv` view from the `Web Browsers`
  category.
- `export-registry-hunter --profile volume-shadow-copies` writes the
  flow-scoped `Windows.Registry.Hunter.VolumeShadowCopies.csv` view from the
  `Volume Shadow Copies` category.
- `export-registry-hunter --profile user-activity` writes the flow-scoped
  `Windows.Registry.Hunter.UserActivity.csv` view from the `User Activity`
  category.
- `export-registry-hunter --profile user-accounts` writes the flow-scoped
  `Windows.Registry.Hunter.UserAccounts.csv` view from the `User Accounts`
  category.
- `export-registry-hunter --profile threat-hunting` writes the flow-scoped
  `Windows.Registry.Hunter.ThreatHunting.csv` view from the `Threat Hunting`
  category.
- `export-registry-hunter --profile third-party-applications` writes the
  flow-scoped `Windows.Registry.Hunter.ThirdPartyApplications.csv` view from
  the `Third Party Applications` category.
- `export-registry-hunter --profile services` writes the flow-scoped
  `Windows.Registry.Hunter.Services.csv` view from the `Services` category.
- `export-registry-hunter --profile network-shares` writes the flow-scoped
  `Windows.Registry.Hunter.NetworkShares.csv` view from the `Network Shares`
  category.
- `export-registry-hunter --profile persistence` writes the flow-scoped
  `Windows.Registry.Hunter.Persistence.csv` view from the `Persistence`
  category.
- `export-registry-hunter --profile program-execution` writes the flow-scoped
  `Windows.Registry.Hunter.ProgramExecution.csv` view from the
  `Program Execution` category.
- `export-registry-hunter --profile microsoft-office` writes the flow-scoped
  `Windows.Registry.Hunter.MicrosoftOffice.csv` view from the
  `Microsoft Office` category.
- `export-registry-hunter --profile microsoft-exchange` writes the
  flow-scoped `Windows.Registry.Hunter.MicrosoftExchange.csv` view from the
  `Microsoft Exchange` category.
- `export-registry-hunter --profile installed-software` writes the
  flow-scoped `Windows.Registry.Hunter.InstalledSoftware.csv` view from the
  `Installed Software` category.
- `export-registry-hunter --profile event-logs` writes the flow-scoped
  `Windows.Registry.Hunter.EventLogs.csv` view from the `Event Logs`
  category.
- `export-registry-hunter --profile devices` writes the flow-scoped
  `Windows.Registry.Hunter.Devices.csv` view from the `Devices` category.
- `export-registry-hunter --profile cloud-storage` writes the flow-scoped
  `Windows.Registry.Hunter.CloudStorage.csv` view from the `Cloud Storage`
  category.
- `export-registry-hunter --profile autoruns` writes the flow-scoped
  `Windows.Registry.Hunter.Autoruns.csv` view from the `Autoruns` category.
- The curated Registry Hunter VQL files live under
  `./skills/windows-collection/references/` and use the flow-scoped source
  form `source(client_id=..., flow_id=..., artifact='Windows.Registry.Hunter/Results')`.
- A requested artifact is considered expected complete when its matched flow is
  no longer in an open state, even if that artifact has no result components in
  `artifacts_with_results`.
- Keep the canonical prior-flow review unbounded through `flows()` when
  checking for the newly queued flow.
