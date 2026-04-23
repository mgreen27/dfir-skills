---
name: windows-analysis
description: Run Windows-focused Velociraptor analysis artifacts against a mapped or live client. Use when you need an investigation overview, want to list Windows artifacts for follow-up work, inspect a specific artifact definition, or run a bounded DetectRaptor.Windows.Detection.Evtx test through the local Velociraptor API.
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
7. Create or reuse an investigation folder for saved outputs. `./investigations/<investigation-name>/` is the default pattern for durable raw outputs that will be chunked or re-reviewed later.
8. Create or reuse the matching investigation wiki under `./investigations/<investigation-name>/wiki/` for iterative analysis.
9. Keep analyst reasoning in the investigation wiki pages, especially `wiki/findings.md`, `wiki/suspicious-artifacts.md`, `wiki/timeline.md`, `wiki/leads.md`, and `wiki/evidence.md`.
10. By default, run collections without date limits unless the user explicitly asks for a bounded time window.
11. Treat unbounded prior-flow review as a critical requirement. Do not add a `LIMIT` to the canonical `flows()` inventory query when reviewing prior collections for analysis.
12. After each meaningful collection wave, decide whether the new evidence answers an existing wiki question or creates a new one, then update the wiki accordingly.
13. In a first-pass DFIR review, explicitly record all potentially malicious disk-side artifacts in `wiki/suspicious-artifacts.md`, even when they are still only leads.
14. When a suspicious binary path is identified, run `Windows.Detection.BinaryHunter` against the exact path and record the resulting hashes, signer details, PE version data, imports, PDB path, and timestamp metadata in the investigation wiki.

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
- `DetectRaptor.Windows.Detection.MFT`
  Use for an initial DetectRaptor pass over MFT-backed file activity when you
  want filename- and path-driven suspicious-file coverage early in the case,
  rather than waiting for a later pivot.
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
- `Windows.System.AppCompatPCA`
  Use for Program Compatibility Assistant launch records. Treat it as launch
  evidence where the PCA dictionary exists, but not as universal execution
  coverage across all Windows versions or all binaries.
- `Windows.Forensics.Prefetch`
  Use for strong binary execution leads, including multiple run timestamps on
  newer Windows versions, where Prefetch is present and enabled.

For deeper-dive follow-up work:

- use `Windows.NTFS.MFT` to pivot into raw NTFS evidence when you need file
  presence, path, timestamp, or filename confirmation beyond higher-level
  artifact summaries
- use `Windows.Search.FileFinder` to target known paths, filenames, extensions,
  or IOC patterns once you have a lead from EVTX, Amcache, Prefetch, or MFT
- use `Windows.Registry.Hunter` when you need a broad registry-centric
  follow-up sweep for persistence, user-activity, autoruns, services, threat
  hunting, or program-execution clues that were not fully explained by the
  lighter first-pass artifacts
- use `Windows.Detection.BinaryHunter` when a suspicious binary path needs
  exact file identity, hashes, signer details, PE metadata, imports, or
  PDB/build-path clues
- use `DetectRaptor.Generic.Detection.YaraFile` when you want content-based
  file triage against suspicious paths or recovered files
- use `DetectRaptor.Generic.Detection.YaraWebshell` when your follow-up work
  includes web roots, scripts, or suspected server-side payloads
- use `DetectRaptor.Generic.Detection.BrowserExtensions` when you need a quick
  view of installed browser add-ons that may explain credential theft,
  persistence, or suspicious user activity
- use `Windows.System.TaskScheduler`, `Windows.Sys.StartupItems`, and
  `Windows.Registry.TaskCache.HiddenTasks` for persistence-focused follow-up
  on dead-disk clients
- list likely artifacts first with `artifacts list`
- inspect parameters with `artifacts show <name>`
- then run a bounded collection

Save results into an investigation folder when you expect follow-up review,
chunking, or multiple passes over the same host, then sync those outputs into
the matching investigation wiki for iterative analysis.

## Commands

List Windows and DetectRaptor artifacts for investigation:

```bash
cd ./velociraptor
./velociraptor --config ./server.config.yaml \
  artifacts list '^DetectRaptor\.Windows\.|^Windows\.'
```

Confirm the mapped or live client is online before analysis:

```bash
cd ./velociraptor
./velociraptor -a ./api_client.yaml \
  --runas api \
  query --format json \
  "SELECT client_id, os_info.hostname as Hostname, timestamp(epoch=last_seen_at) as LastSeen FROM clients() WHERE os_info.hostname =~ '^base-dc$' OR os_info.fqdn =~ '^base-dc$' ORDER BY LastSeen DESC LIMIT 1"
```

If `LastSeen` is stale or missing, stop and restore the mapped client first.
Collections queued through the API will not run until the client is polling the
server.

Narrow the list to likely first-pass triage artifacts:

```bash
cd ./velociraptor
./velociraptor --config ./server.config.yaml \
  artifacts list '^DetectRaptor\.Windows\.Detection\.|^Windows\.EventLogs\.'
```

Review evidence-of-execution artifact descriptions before collecting:

```bash
cd ./velociraptor
for artifact in \
  Windows.Detection.Amcache \
  Windows.Forensics.Bam \
  Windows.Forensics.Timeline \
  Windows.Registry.UserAssist \
  Windows.Registry.AppCompatCache \
  Windows.System.AppCompatPCA \
  Windows.Forensics.Prefetch
do
  ./velociraptor --config ./server.config.yaml \
    artifacts show "$artifact"
done
```

Inspect a deeper-dive evidence-of-execution artifact:

```bash
cd ./velociraptor
./velociraptor --config ./server.config.yaml \
  artifacts show Windows.NTFS.MFT
```

Inspect a targeted follow-up hunting artifact:

```bash
cd ./velociraptor
./velociraptor --config ./server.config.yaml \
  artifacts show Windows.Search.FileFinder
```

Inspect the broad registry follow-up artifact:

```bash
cd ./velociraptor
./velociraptor --config ./server.config.yaml \
  artifacts show Windows.Registry.Hunter
```

Inspect persistence-focused follow-up artifacts:

```bash
cd ./velociraptor
for artifact in \
  Windows.Sys.StartupItems \
  Windows.System.Services \
  Windows.System.TaskScheduler \
  Windows.Registry.TaskCache.HiddenTasks \
  Windows.Remediation.ScheduledTasks
do
  ./velociraptor --config ./server.config.yaml \
    artifacts show "$artifact"
done
```

Inspect a generic Yara follow-up artifact:

```bash
cd ./velociraptor
./velociraptor --config ./server.config.yaml \
  artifacts show DetectRaptor.Generic.Detection.YaraFile
```

Inspect the webshell-focused Yara artifact:

```bash
cd ./velociraptor
./velociraptor --config ./server.config.yaml \
  artifacts show DetectRaptor.Generic.Detection.YaraWebshell
```

Inspect the browser-extension follow-up artifact:

```bash
cd ./velociraptor
./velociraptor --config ./server.config.yaml \
  artifacts show DetectRaptor.Generic.Detection.BrowserExtensions
```

Inspect the suspicious-binary follow-up artifact:

```bash
cd ./velociraptor
./velociraptor --config ./server.config.yaml \
  artifacts show Windows.Detection.BinaryHunter
```

Inspect a specific artifact before running it:

```bash
cd ./velociraptor
./velociraptor --config ./server.config.yaml \
  artifacts show DetectRaptor.Windows.Detection.Evtx
```

Inspect the initial MFT-driven DetectRaptor artifact:

```bash
cd ./velociraptor
./velociraptor --config ./server.config.yaml \
  artifacts show DetectRaptor.Windows.Detection.MFT
```

Resolve a hostname to the most recent client id:

```bash
cd ./velociraptor
./velociraptor -a ./api_client.yaml \
  --runas api \
  query --format json \
  "SELECT client_id, os_info.hostname as Hostname, os_info.fqdn as Fqdn, timestamp(epoch=last_seen_at) as LastSeen FROM clients() WHERE os_info.hostname =~ '^base-dc$' OR os_info.fqdn =~ '^base-dc$' ORDER BY LastSeen DESC LIMIT 1"
```

Review prior collections on the client with timestamps, newest first. This is a
critical requirement and must not use `LIMIT`:

```bash
cd ./velociraptor
./velociraptor -a ./api_client.yaml \
  --runas api \
  query --format json \
  "SELECT session_id, timestamp(epoch=create_time) as Created, state, total_collected_rows, artifacts_with_results, request.specs[0].artifact as ArtifactName FROM flows(client_id='C.6d94a75e45cb9367') ORDER BY create_time DESC"
```

Use that latest-first flow inventory to identify recent collections before
checking for an exact artifact-and-parameter match.

Check whether the same collection already ran with the same parameters:

```bash
cd ./velociraptor
./velociraptor -a ./api_client.yaml \
  --runas api \
  query --format json \
  "SELECT session_id, state, timestamp(epoch=create_time) as Created, total_collected_rows, serialize(format='json', item=request.specs[0].parameters) as ParametersJson FROM flows(client_id='C.6d94a75e45cb9367') WHERE request.specs[0].artifact = 'DetectRaptor.Windows.Detection.Evtx' AND serialize(format='json', item=request.specs[0].parameters) =~ 'DateAfter' AND serialize(format='json', item=request.specs[0].parameters) =~ '2018-04-20T00:00:00Z' AND serialize(format='json', item=request.specs[0].parameters) =~ 'DateBefore' AND serialize(format='json', item=request.specs[0].parameters) =~ '2018-04-30T00:00:00Z' AND serialize(format='json', item=request.specs[0].parameters) =~ 'VSSAnalysisAge' AND serialize(format='json', item=request.specs[0].parameters) =~ '0' ORDER BY create_time DESC"
```

If that query returns a finished flow with the same parameter set, review or
reuse the prior results before queueing another identical collection. Adapt the
artifact name and parameter values in the query to match the collection you are
about to run.

Set reusable shell variables first:

```bash
INVESTIGATION_ID=shieldbase-intrusion
SYSTEM_NAME=base-dc
CLIENT_ID=C.6d94a75e45cb9367
mkdir -p "./investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/velociraptor"
./skills/investigation/scripts/init_investigation.sh "$INVESTIGATION_ID"
```

Queue DetectRaptor EVTX with no date limits by client id:

```bash
cd ./velociraptor
./velociraptor -a ./api_client.yaml \
  --definitions ./artifact_definitions \
  --runas api \
  artifacts collect DetectRaptor.Windows.Detection.Evtx \
  --client_id "$CLIENT_ID" \
  --org_id root
```

Queue BinaryHunter against a suspicious exact path:

```bash
cd ./velociraptor
./velociraptor -a ./api_client.yaml \
  --runas api \
  artifacts collect Windows.Detection.BinaryHunter \
  --client_id C.0c88f4ff29f4c938 \
  --org_id root \
  --args TargetGlob='C:/Windows/subject_srv.exe' \
  --args Accessor='auto' \
  --args AuthenticodeRegex='.' \
  --args PEInformationRegex='.'
```

After the flow finishes, save the server-side results directly into the
investigation folder. For larger collections, use `jsonl` as the safe default:

```bash
cd ./velociraptor
./velociraptor -a ./api_client.yaml \
  --runas api \
  query --format jsonl \
  "SELECT * FROM source(client_id='${CLIENT_ID}', flow_id='F.D7IRINBEJ3OVI', artifact='DetectRaptor.Windows.Detection.Evtx')" \
  > "../investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/velociraptor/${SYSTEM_NAME}-detectraptor-evtx.jsonl"
```

Save AppCompatCache results directly from a finished flow:

```bash
cd ./velociraptor
./velociraptor -a ./api_client.yaml \
  --runas api \
  query --format jsonl \
  "SELECT * FROM source(client_id='${CLIENT_ID}', flow_id='F.D7IRLJON2IIHQ', artifact='Windows.Registry.AppCompatCache')" \
  > "../investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/velociraptor/${SYSTEM_NAME}-appcompatcache.jsonl"
```

Save BinaryHunter results directly from a finished flow:

```bash
cd ./velociraptor
./velociraptor -a ./api_client.yaml \
  --runas api \
  query --format jsonl \
  "SELECT * FROM source(client_id='${CLIENT_ID}', flow_id='F.<flow_id>', artifact='Windows.Detection.BinaryHunter')" \
  > "../investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/velociraptor/${SYSTEM_NAME}-binaryhunter-subject-srv.jsonl"
```

Example registry-hunter collection for a dead-disk image:

```bash
cd ./velociraptor
./velociraptor -a ./api_client.yaml \
  --runas api \
  artifacts collect Windows.Registry.Hunter \
  --client_id C.6d94a75e45cb9367 \
  --org_id root \
  --args RemappingStrategy='None' \
  --args CollectionPolicy='None' \
  --args Categories='["Persistence","Program Execution","Services","Threat Hunting","User Activity"]'
```

Troubleshooting:

- If `Windows.Registry.Hunter` logs `Unknown filesystem accessor registry` on a
  dead-disk client, the problem is usually the artifact's
  `RemappingStrategy`, not the host `remapping.yaml`.
- For dead-disk images in this repo, rerun it with
  `RemappingStrategy='None'`, or use the dedicated
  `windows-registry-analysis` skill directly.

Example persistence-review collections for a dead-disk image:

```bash
cd ./velociraptor
./velociraptor -a ./api_client.yaml \
  --runas api \
  artifacts collect Windows.Sys.StartupItems \
  --client_id "$CLIENT_ID" \
  --org_id root \
  --format jsonl \
  > "../investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/velociraptor/${SYSTEM_NAME}-startupitems.jsonl"

./velociraptor -a ./api_client.yaml \
  --runas api \
  artifacts collect Windows.System.TaskScheduler \
  --client_id "$CLIENT_ID" \
  --org_id root \
  --format jsonl \
  > "../investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/velociraptor/${SYSTEM_NAME}-taskscheduler.jsonl"

./velociraptor -a ./api_client.yaml \
  --runas api \
  artifacts collect Windows.Registry.TaskCache.HiddenTasks \
  --client_id "$CLIENT_ID" \
  --org_id root \
  --format jsonl \
  > "../investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/velociraptor/${SYSTEM_NAME}-hidden-tasks.jsonl"
```

Default investigation layout:

```text
./investigations/<investigation-name>/
  evidence/
    systems/
      <target>/
        velociraptor/
          <target>-<artifact>.jsonl
  wiki/
    analysis.md
    hot.md
    evidence.md
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
  `./investigations/<investigation-name>/evidence/systems/<target>/velociraptor/`.
- Keep the case `wiki/` up to date with validated findings, suspicious
  artifacts, caveats, leads, timeline entries, and next actions.
- After a collection wave, run the investigation-ingest skill so the
  artifact index and hot cache reflect the latest raw outputs.
- Use the updated wiki state to decide whether another targeted collection is
  needed. The collection workflow and the wiki-writing workflow are meant to
  feed each other.
- When a suspicious binary is confirmed or even remains a strong lead, use
  `Windows.Detection.BinaryHunter` as the standard exact-path follow-up and
  record the exact file path, MD5, SHA1, SHA256, file version, PE compile
  timestamp, signer subject and issuer, import hash, notable imports, and PDB
  path in the case wiki.
- For dead-disk persistence work, `Windows.System.TaskScheduler` is usually the
  best on-disk task review artifact. `Windows.Sys.StartupItems` is a good
  low-cost autorun check, and `Windows.Registry.TaskCache.HiddenTasks` is a
  targeted check for missing-`SD` hidden-task abuse.
- `Windows.System.Services` is WMI-backed and can be sparse on dead-disk
  clients. Treat a `0` row result there as a collection limitation, not a
  clearing condition.
- `Windows.Remediation.ScheduledTasks` is primarily a remediation artifact. Use
  it carefully and do not treat it as a broad scheduled-task discovery source.
- `Windows.Registry.Hunter` is intentionally a heavyweight follow-up artifact.
  On dead-disk work in this repo, prefer `RemappingStrategy='None'` and a
  narrowed category or description filter unless you explicitly want the full
  sweep.
- Prefer retrieving finished results with `source(client_id=..., flow_id=...,
  artifact=...)` and saving them as `.jsonl` for durable review. Small outputs
  can still be written as `.json`, but `.jsonl` is the safer default for large
  collections because the CLI may emit multiple JSON arrays in `json` mode.
  Only use `--output ...zip` when you explicitly want the full Velociraptor
  collection package.
