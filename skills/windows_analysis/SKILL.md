---
name: windows_analysis
description: Run Windows-focused Velociraptor analysis artifacts against a mapped or live client, especially DetectRaptor and built-in Windows event-log artifacts. Use when you need an investigation overview, want to list Windows artifacts for follow-up work, inspect a specific artifact definition, or run a bounded DetectRaptor.Windows.Detection.Evtx test through the local Velociraptor API.
---

# Windows Analysis

Use the commands below directly from the repo root or from `./velociraptor/`
to list Windows-focused artifacts or collect a targeted analysis artifact
against a Velociraptor client.

## Workflow

1. Confirm the repo-local Velociraptor workspace exists under `./velociraptor`.
2. Reuse the local API client config from `./velociraptor/api_client.yaml`.
3. Confirm the target client is online and has a recent `LastSeen` timestamp.
4. Resolve the target by hostname or use a known client id directly.
5. Check whether the same collection has already been run with the same parameters.
6. List or inspect available artifacts before running broader collections.
7. Create or reuse an investigation folder for saved outputs. `./investigations/<investigation-name>/` is the default pattern for durable outputs that will be chunked or re-reviewed later. The investigation name can be the hostname, a case number, or a descriptive name that fits your workflow.
8. Keep an `investigation-notes.md` file in that folder for operational context, flow ids, commands, and analyst scratch notes.
9. Keep an `investigation-results.md` file in that folder for DFIR findings, interpretation, confidence, and next actions.
10. By default, run collections without date limits unless the user explicitly asks for a bounded time window.
11. Treat unbounded prior-flow review as a critical requirement. Do not add a `LIMIT` to the canonical `flows()` inventory query when reviewing prior collections for analysis.

## Investigation Overview

Start with these artifact families during Windows triage:

- `DetectRaptor.Windows.Detection.Evtx`
  Use for a broad detection sweep across Security, System, Defender, BITS, and
  PowerShell event logs.
- `DetectRaptor.Windows.Detection.Applications`
  Use for installed-application and application-execution style leads that can
  help explain what tooling was present on the host.
- `DetectRaptor.Windows.Detection.Powershell.PSReadline`
  Use for PowerShell command-history review when you need operator activity or
  hands-on-keyboard evidence.
- `Windows.EventLogs.EvtxHunter`
  Use when you already have a string, path, event id, or IOC regex and want a
  direct event-log hunt.
- `DetectRaptor.Windows.Detection.ZoneIdentifier`
  Use for download and MOTW style leads from `Zone.Identifier` alternate data
  streams.

### Evidence Of Execution

These artifacts are the main evidence-of-execution workflow. Review the
artifact description with `artifacts show <name>` before interpreting results.
This is mandatory because several of these artifacts have important caveats.

- `Windows.Detection.Amcache`
  Use for SHA1-backed Amcache execution and installation metadata. Treat
  secondary fields as guidance only, and remember this artifact only returns
  entries that include a SHA1.
- `Windows.Forensics.Bam`
  Use for full-path and last-execution-style BAM records on Windows 10 1709+
  systems. Good for recent execution context, but only where BAM data exists.
- `Windows.Forensics.Timeline`
  Use for `ActivitiesCache.db` review of recently used applications and files.
  Treat this as user activity context, not a standalone execution verdict, and
  note the artifact is marked deprecated in favor of `Generic.Forensic.SQLiteHunter`.
- `Windows.Registry.UserAssist`
  Use for Explorer-launched program activity. Do not treat it as complete
  execution coverage because command-line launches do not appear here, and some
  viewing/access patterns can update counts or times.
- `Windows.Registry.AppCompatCache`
  Use for shimcache-style path and compatibility evidence. On Windows 10+ an
  execution flag of `1` indicates execution, but execution semantics are weaker
  on older Windows versions.
- `Windows.Forensics.Prefetch`
  Use for strong binary execution leads, including multiple run timestamps on
  newer Windows versions, where Prefetch is present and enabled.

For deeper-dive follow-up work:

- use `Windows.NTFS.MFT` to pivot into raw NTFS evidence when you need file
  presence, path, timestamp, or filename confirmation beyond higher-level
  artifact summaries
- use `Windows.Search.FileFinder` to target known paths, filenames, extensions,
  or IOC patterns once you have a lead from EVTX, Amcache, Prefetch, or MFT
- use `DetectRaptor.Generic.Detection.YaraFile` when you want content-based
  file triage against suspicious paths or recovered files
- use `DetectRaptor.Generic.Detection.YaraWebshell` when your follow-up work
  includes web roots, scripts, or suspected server-side payloads
- use `DetectRaptor.Generic.Detection.BrowserExtensions` when you need a quick
  view of installed browser add-ons that may explain credential theft,
  persistence, or suspicious user activity
- list likely artifacts first with `artifacts list`
- inspect parameters with `artifacts show <name>`
- then run a bounded collection

Save results into an investigation folder when you expect follow-up review,
chunking, or multiple passes over the same host.

Keep two Markdown files in the investigation folder:

- `investigation-notes.md` for current client status, flow ids, commands,
  analyst scratch notes, and execution context
- `investigation-results.md` for the DFIR narrative, findings, confidence,
  caveats, and next investigative actions

## Commands

List Windows and DetectRaptor artifacts for investigation:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor --config /Users/matt/git/dfir-skills/velociraptor/server.config.yaml \
  artifacts list '^DetectRaptor\.Windows\.|^Windows\.'
```

Confirm the mapped or live client is online before analysis:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --runas api \
  query --format json \
  "SELECT client_id, os_info.hostname as Hostname, timestamp(epoch=last_seen_at) as LastSeen FROM clients() WHERE os_info.hostname =~ '^base-dc$' OR os_info.fqdn =~ '^base-dc$' ORDER BY LastSeen DESC LIMIT 1"
```

If `LastSeen` is stale or missing, stop and restore the mapped client first.
Collections queued through the API will not run until the client is polling the
server.

Narrow the list to likely first-pass triage artifacts:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor --config /Users/matt/git/dfir-skills/velociraptor/server.config.yaml \
  artifacts list '^DetectRaptor\.Windows\.Detection\.|^Windows\.EventLogs\.'
```

Review evidence-of-execution artifact descriptions before collecting:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
for artifact in \
  Windows.Detection.Amcache \
  Windows.Forensics.Bam \
  Windows.Forensics.Timeline \
  Windows.Registry.UserAssist \
  Windows.Registry.AppCompatCache \
  Windows.Forensics.Prefetch
do
  ./velociraptor --config /Users/matt/git/dfir-skills/velociraptor/server.config.yaml \
    artifacts show "$artifact"
done
```

Inspect a deeper-dive evidence-of-execution artifact:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor --config /Users/matt/git/dfir-skills/velociraptor/server.config.yaml \
  artifacts show Windows.NTFS.MFT
```

Inspect a targeted follow-up hunting artifact:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor --config /Users/matt/git/dfir-skills/velociraptor/server.config.yaml \
  artifacts show Windows.Search.FileFinder
```

Inspect a generic Yara follow-up artifact:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor --config /Users/matt/git/dfir-skills/velociraptor/server.config.yaml \
  artifacts show DetectRaptor.Generic.Detection.YaraFile
```

Inspect the webshell-focused Yara artifact:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor --config /Users/matt/git/dfir-skills/velociraptor/server.config.yaml \
  artifacts show DetectRaptor.Generic.Detection.YaraWebshell
```

Inspect the browser-extension follow-up artifact:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor --config /Users/matt/git/dfir-skills/velociraptor/server.config.yaml \
  artifacts show DetectRaptor.Generic.Detection.BrowserExtensions
```

Inspect a specific artifact before running it:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor --config /Users/matt/git/dfir-skills/velociraptor/server.config.yaml \
  artifacts show DetectRaptor.Windows.Detection.Evtx
```

Resolve a hostname to the most recent client id:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --runas api \
  query --format json \
  "SELECT client_id, os_info.hostname as Hostname, os_info.fqdn as Fqdn, timestamp(epoch=last_seen_at) as LastSeen FROM clients() WHERE os_info.hostname =~ '^base-dc$' OR os_info.fqdn =~ '^base-dc$' ORDER BY LastSeen DESC LIMIT 1"
```

Review prior collections on the client with timestamps, newest first. This is a
critical requirement and must not use `LIMIT`:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --runas api \
  query --format json \
  "SELECT session_id, timestamp(epoch=create_time) as Created, state, total_collected_rows, artifacts_with_results, request.specs[0].artifact as ArtifactName FROM flows(client_id='C.6d94a75e45cb9367') ORDER BY create_time DESC"
```

Use that latest-first flow inventory to identify recent collections before
checking for an exact artifact-and-parameter match.

Check whether the same collection already ran with the same parameters:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --runas api \
  query --format json \
  "SELECT session_id, state, timestamp(epoch=create_time) as Created, total_collected_rows, serialize(format='json', item=request.specs[0].parameters) as ParametersJson FROM flows(client_id='C.6d94a75e45cb9367') WHERE request.specs[0].artifact = 'DetectRaptor.Windows.Detection.Evtx' AND serialize(format='json', item=request.specs[0].parameters) =~ 'DateAfter' AND serialize(format='json', item=request.specs[0].parameters) =~ '2018-04-20T00:00:00Z' AND serialize(format='json', item=request.specs[0].parameters) =~ 'DateBefore' AND serialize(format='json', item=request.specs[0].parameters) =~ '2018-04-30T00:00:00Z' AND serialize(format='json', item=request.specs[0].parameters) =~ 'VSSAnalysisAge' AND serialize(format='json', item=request.specs[0].parameters) =~ '0' ORDER BY create_time DESC"
```

If that query returns a finished flow with the same parameter set, review or
reuse the prior results before queueing another identical collection. Adapt the
artifact name and parameter values in the query to match the collection you are
about to run.

Create an investigation folder for durable outputs:

```bash
mkdir -p /Users/matt/git/dfir-skills/investigations/base-dc/velociraptor
touch /Users/matt/git/dfir-skills/investigations/base-dc/investigation-notes.md
touch /Users/matt/git/dfir-skills/investigations/base-dc/investigation-results.md
```

Queue DetectRaptor EVTX with no date limits by client id:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --definitions /Users/matt/git/dfir-skills/velociraptor/artifact_definitions \
  --runas api \
  artifacts collect DetectRaptor.Windows.Detection.Evtx \
  --client_id C.6d94a75e45cb9367 \
  --org_id root
```

After the flow finishes, save the server-side results directly into the
investigation folder. For larger collections, use `jsonl` as the safe default:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --runas api \
  query --format jsonl \
  "SELECT * FROM source(client_id='C.6d94a75e45cb9367', flow_id='F.D7IRINBEJ3OVI', artifact='DetectRaptor.Windows.Detection.Evtx')" \
  > /Users/matt/git/dfir-skills/investigations/base-dc/velociraptor/base-dc-detectraptor-evtx.jsonl
```

Save AppCompatCache results directly from a finished flow:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --runas api \
  query --format jsonl \
  "SELECT * FROM source(client_id='C.6d94a75e45cb9367', flow_id='F.D7IRLJON2IIHQ', artifact='Windows.Registry.AppCompatCache')" \
  > /Users/matt/git/dfir-skills/investigations/base-dc/velociraptor/base-dc-appcompatcache.jsonl
```

Default investigation layout:

```text
./investigations/<investigation-name>/
  velociraptor/
    <target>-<artifact>.jsonl
  investigation-notes.md
  investigation-results.md
```

## Notes

- This skill expects `prep-dfir-tools` to have already staged and initialized
  Velociraptor under `./velociraptor/`.
- Use `api_client.yaml` for hostname lookups, client-online checks, and client
  collections. That is the path that schedules real flows on the Velociraptor
  server so the collections are visible in the GUI.
- When collecting DetectRaptor artifacts through the API, pass the local
  `artifact_definitions` directory so the CLI can resolve the custom artifact
  names before queueing the flow.
- Use the local `server.config.yaml` for artifact inspection commands such as
  `artifacts list` and `artifacts show`.
- The default artifact is `DetectRaptor.Windows.Detection.Evtx`.
- The default result output directory is
  `./investigations/<investigation-name>/velociraptor/`.
- Keep `./investigations/<investigation-name>/investigation-notes.md`
  updated with run context and observations.
- Keep `./investigations/<investigation-name>/investigation-results.md`
  updated with validated findings, caveats, and next actions.
- Prefer retrieving finished results with `source(client_id=..., flow_id=...,
  artifact=...)` and saving them as `.jsonl` for durable review. Small outputs
  can still be written as `.json`, but `.jsonl` is the safer default for large
  collections because the CLI may emit multiple JSON arrays in `json` mode.
  Only use `--output ...zip` when you explicitly want the full Velociraptor
  collection package.
