# dfir-skills

A DFIR skills repository for automated incident response and iterative
analysis. Each skill lives in its own folder and contains a `SKILL.md`. A
`scripts/` subfolder is only needed when the skill actually ships executable
helpers.

The repo assumes a local Python virtual environment at `./venv`. Tool prep
stages tools in the repo root by default.

## Operating Model

- Raw DFIR outputs live under
  `./investigations/<investigation_id>/evidence/systems/<system>/`.
- The canonical structured case record lives under
  `./investigations/<investigation_id>/spreadsheet-of-doom/`.
- Iterative analyst reasoning lives under
  `./investigations/<investigation_id>/wiki/`.
- Velociraptor runs from `./velociraptor/`.
- Volatility 3 runs from `./volatility3/`.
- The default investigation goal is a full DFIR pass over the evidence that
  identifies and records all potentially malicious artifacts before deeper
  workflow-specific review.
- The analysis loop is iterative: write findings into the wiki, let open
  questions in the wiki drive the next collection step, then feed those new
  results back into the wiki.
- The default review posture is export-first: prefer existing analyst-ready
  CSV exports over new collection, and recollect only when explicitly asked or
  when the current exports cannot answer the evidence question.

## Repository Layout

```text
investigations/
  <investigation_id>/
    evidence/
      systems/
        <system>/
          velociraptor/
          volatility3/
      virustotal/
    spreadsheet-of-doom/
      timeline.csv
      systems.csv
      asset-map.csv
      users.csv
      host-indicators.csv
      network-indicators.csv
      task-tracker.csv
      evidence-tracker.csv
      keywords.csv
    <investigation_id>_SoD.xlsx
    wiki/
      analysis.md
      spreadsheet-of-doom.md
      investigative-questions.md
      evidence.md
      hot.md
      log.md
      artifacts/
      meta/

skills/
  prep-dfir-tools/
  velociraptor-server-watchdog/
  add-velociraptor-mapped-client/
  detect-dfir-collection-type/
  investigation/
  investigation-ingest/
  investigation-query/
  windows-analysis/
  windows-collection/
  windows-timeline/
  windows-collection-live/
  memory-analysis/
  virustotal/
```

## Spreadsheet Of Doom

The investigation record is now spreadsheet-first:

- `timeline.csv` for ordered events and timestamps
- `systems.csv` for all machines in scope
- `asset-map.csv` for host-to-IP mappings and unresolved recurring source IPs
- `users.csv` for account context
- `host-indicators.csv` for file, binary, and host-resident indicators
- `network-indicators.csv` for infrastructure and communications pivots
- `task-tracker.csv` for leads, follow-up work, and unresolved questions
- `evidence-tracker.csv` for evidence intake and provenance
- `keywords.csv` for high-fidelity forensic search terms

Recommended storage model:

- Keep Spreadsheet of Doom sheets as CSV source of truth.
- Keep `spreadsheet-of-doom/`, `wiki/`, and `evidence/` as first-class
  siblings under the investigation root.
- Keep raw Velociraptor or Volatility outputs under `evidence/systems/<system>/`.
- Generate a root-level XLSX workbook named `<investigation_id>_SoD.xlsx`
  after each sync as a convenience view,
  not as the canonical repository format.
- In `windows-collection`, request-scoped state now lives under
  `evidence/systems/<system>/velociraptor/host-collection/requests/<request_id>/state.json`,
  while `host-collection-state.json` remains the latest-state compatibility
  pointer for the host.

## Skills

### 1. Prep DFIR Tools

Path: `skills/prep-dfir-tools/`

Purpose:

- Prepare common DFIR tools for macOS and Linux hosts.
- Support Velociraptor, Volatility 3, and Sleuth Kit.
- Bootstrap the repo-local `./venv`.
- Install Python support for the Velociraptor API and broader Volatility 3
  plugin coverage.

Run:

```bash
./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh
```

Useful targets:

```bash
./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t venv
./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t velociraptor
```

### 2. Velociraptor Server Watchdog

Path: `skills/velociraptor-server-watchdog/`

Purpose:

- Keep the local Velociraptor GUI, API, and client-frontend listeners alive.
- Reuse an already healthy GUI process when one exists.
- Restart the GUI if listeners disappear or the API stops answering a trivial
  health query.
- Write runtime state into `./velociraptor/server-status.env` and
  `./velociraptor/server-session.env`.

Run:

```bash
./skills/velociraptor-server-watchdog/scripts/start_server_watchdog.sh
```

Operational note:

- The watchdog checks both the expected listeners and an API
  `SELECT 1 AS ok FROM scope()` query before it treats the server as healthy.
- In the current Codex environment, the most reliable way to keep it alive is
  still to run the watchdog in a dedicated live session.

### 3. Add Velociraptor Mapped Client

Path: `skills/add-velociraptor-mapped-client/`

Purpose:

- Reuse or start the local Velociraptor GUI workspace.
- Generate a dead-disk remapping for an offline Windows image or mounted
  Windows directory.
- Launch a supervised background mapped client so the evidence appears in GUI
  mode and stays online during analysis.
- Derive the mapped client hostname from the image or folder name.

Run:

```bash
./skills/add-velociraptor-mapped-client/scripts/add_mapped_client.sh /path/to/image.E01
```

Operational note:

- When the GUI is missing, this skill now starts it through the server
  watchdog instead of spawning an unsupervised GUI process.
- Each mapped client now has a local supervisor under
  `./velociraptor/mapped-clients/<name>/supervisor.pid`.
- The supervisor restarts the client if the process exits or if the API
  `LastSeen` timestamp goes stale.

### 4. Detect DFIR Collection Type

Path: `skills/detect-dfir-collection-type/`

Purpose:

- Detect whether a path contains a disk image, memory image, process dump,
  live-response collection, mixed folder, or an unknown artefact set.

Run:

```bash
python3 ./skills/detect-dfir-collection-type/scripts/detect_collection.py /path/to/evidence
```

### 5. Investigation

Path: `skills/investigation/`

Purpose:

- Scaffold an investigation-centric case folder for iterative DFIR analysis.
- Create a Spreadsheet of Doom under the investigation directory.
- Keep structured case facts in CSV while keeping short narrative analysis in
  `wiki/`.
- Provide a standard case layout that can be refreshed over multiple analysis
  passes.

Run:

```bash
./skills/investigation/scripts/init_investigation.sh shieldbase-intrusion
```

### 6. Investigation Ingest

Path: `skills/investigation-ingest/`

Purpose:

- Sync raw case outputs from `./investigations/<investigation_id>/` into the
  investigation case folder.
- Build file-level artifact notes under `wiki/artifacts/`.
- Refresh the case hot cache and sync status.
- Refresh Spreadsheet of Doom links for the active investigation record.

Run:

```bash
./skills/investigation-ingest/scripts/sync_investigation.sh shieldbase-intrusion
```

### 7. Investigation Query

Path: `skills/investigation-query/`

Purpose:

- Answer case questions from the investigation `wiki/` and Spreadsheet of Doom.
- Prefer the accumulated analysis in `wiki/hot.md`, `wiki/analysis.md`, and
  the Spreadsheet of Doom sheets before reopening raw files.

### 8. Windows Analysis

Path: `skills/windows-analysis/`

Purpose:

- Run Windows-focused Velociraptor analysis artifacts through the local API.
- Confirm the target client is online before queueing targeted analysis.
- Use the separate `windows-collection` skill for machine-wide collection and
  reuse checks.
- Write collection outputs into
  `./investigations/<investigation_id>/evidence/systems/<system>/velociraptor/`.
- Keep iterative analysis in `./investigations/<investigation_id>/wiki/`.
- Treat unbounded `flows()` review as a critical requirement before analysis.
- The default first-pass artifact set includes DetectRaptor EVTX, Applications,
  PSReadline, ZoneIdentifier, and MFT coverage before deeper pivots.
- The evidence-of-execution set also includes `Windows.System.AppCompatPCA`,
  with the normal requirement to review the artifact description before using
  it as execution evidence.
- `Windows.Forensics.RecentFileCache` is also part of the evidence-of-execution
  set for older Windows systems where the cache exists.
- `Windows.Forensics.SRUM` is also part of the evidence-of-execution set in
  this repo, with per-scope CSV export for its application, execution, and
  network usage views.
- `Windows.Registry.Hunter` is also part of the repo's evidence-of-execution
  workflow, because it can supply broad registry-backed execution context
  alongside later persistence, services, and user-activity follow-up.
- The baseline Windows collection now also includes a dedicated
  `lateral-movement` section for public-IP auth, RDP auth, explicit logon,
  `MountPoints2`, and suspicious service creation via `COMSPEC`.
- The baseline Windows collection persistence section now includes
  `Windows.System.Services`, `Windows.Registry.Hunter[all]`,
  `Windows.Persistence.PermanentWMIEvents`, and
  `Windows.Sysinternals.Autoruns` in addition to startup items, scheduled
  tasks, and hidden task-cache review. On mapped dead-disk clients, the WMI
  and Sysinternals Autoruns artifacts can still be sparse or non-functional.
- Suspicious binaries found during analysis should be reviewed with
  `Windows.Detection.BinaryHunter` so the case records exact hashes, signer
  details, PE metadata, imports, and PDB/build-path clues instead of relying
  only on path-based suspicion.
- On dead-disk clients, persistence follow-up should prefer
  `Windows.System.TaskScheduler`, `Windows.Sys.StartupItems`, and
  `Windows.Registry.TaskCache.HiddenTasks` before relying on the WMI-backed
  `Windows.System.Services` artifact.
- On dead-disk clients, run `Windows.Registry.Hunter` with
  `RemappingStrategy='None'`.

Examples:

```bash
./skills/investigation/scripts/init_investigation.sh shieldbase-intrusion
mkdir -p ./investigations/shieldbase-intrusion/evidence/systems/base-dc/velociraptor
cd ./velociraptor && ./velociraptor -a ./api_client.yaml --runas api query --format json "SELECT session_id, timestamp(epoch=create_time) as Created, state, total_collected_rows, artifacts_with_results, request.specs[0].artifact as ArtifactName FROM flows(client_id='C.6d94a75e45cb9367') ORDER BY create_time DESC"
cd ./velociraptor && ./velociraptor -a ./api_client.yaml --definitions ./artifact_definitions --runas api artifacts collect DetectRaptor.Windows.Detection.Evtx --client_id C.6d94a75e45cb9367 --org_id root
cd ./velociraptor && ./velociraptor -a ./api_client.yaml --runas api query --format jsonl "SELECT * FROM source(client_id='C.6d94a75e45cb9367', flow_id='F.D7IRINBEJ3OVI', artifact='DetectRaptor.Windows.Detection.Evtx')" > ./investigations/shieldbase-intrusion/evidence/systems/base-dc/velociraptor/base-dc-detectraptor-evtx.jsonl
./skills/investigation-ingest/scripts/sync_investigation.sh shieldbase-intrusion
```

### 8a. Windows Collection

Path: `skills/windows-collection/`

Purpose:

- Queue and reuse machine-wide Windows Velociraptor collection flows for the
  repo's dead-disk or offline mapped-client workflow, then automatically
  export finished results to CSV.
- Treat collection as one flow per artifact, not one bulk host flow.
- Save durable collection metadata under each host's
  `velociraptor/host-collection/`.
- Poll collection state until the requested set is complete.
- Save generic CSV exports under each host's `velociraptor/exports/` tree as
  part of the normal `queue`, `ensure`, or `poll` workflow unless export is
  explicitly disabled.

Run:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  ensure \
  --investigation-id shieldbase-intrusion \
  --host base-dc \
  --collection-type all
```

Lateral-movement focused collection:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  ensure \
  --investigation-id shieldbase-intrusion \
  --host base-dc \
  --collection-type lateral-movement
```

Curated Registry Hunter Program Execution export:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  export-registry-hunter \
  --investigation-id shieldbase-intrusion \
  --host base-dc \
  --profile execution
```

### 8b. Windows Timeline

Path: `skills/windows-timeline/`

Purpose:

- Run a bounded post-analysis timeline pivot after iterative review has
  already identified a suspicious time window.
- Reuse the `windows-collection` engine to query `Windows.NTFS.MFT` and
  `Windows.EventLogs.EvtxHunter` with the same `DateAfter` and `DateBefore`
  bounds.
- Add optional MFT and EVTX filters so the pivot can widen or confirm adjacent
  activity without rerunning the full baseline collection.
- Save durable per-run exports under the host `velociraptor/exports/` tree
  with unique suffixes for bounded follow-up runs.

Run:

```bash
./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py \
  ensure \
  --investigation-id shieldbase-intrusion \
  --host base-dc \
  --collection-type timeline \
  --date-after 2026-05-01T00:00:00Z \
  --date-before 2026-05-01T06:00:00Z \
  --evtx-ioc-regex 'powershell|cmd\\.exe|rundll32|wmic'
```

### 8c. Windows Collection Live

Path: `skills/windows-collection-live/`

Purpose:

- Reuse the same collection/export engine as `windows-collection`, but against
  a live remote Velociraptor environment.
- Require an explicit remote `api_client.yaml` instead of assuming the
  repo-local `./velociraptor/api_client.yaml`.
- Keep the live/remote workflow separate from the dead-disk/offline workflow
  so future live-only artifacts can diverge cleanly.

Run:

```bash
./venv/bin/python ./skills/windows-collection-live/scripts/run_windows_collection_live.py \
  --api-client /path/to/remote-api_client.yaml \
  ensure \
  --investigation-id shieldbase-intrusion \
  --host live-host-01 \
  --collection-type execution
```

### 9. Memory Analysis

Path: `skills/memory-analysis/`

Purpose:

- Run Volatility 3 triage against a Windows memory image with repo-local
  tooling.
- Write text outputs into
  `./investigations/<investigation_id>/evidence/systems/<system>/volatility3/`.
- Keep iterative analysis in the investigation `wiki/` instead of flat case
  markdown files.
- Use scan-based plugins and `-vvv` diagnostics when richer plugins fail.

### 10. IOC Tracker

Path: `skills/ioc-tracker/`

Purpose:

- Keep a shared cross-host IOC and adversary-tracking view under
  the investigation Spreadsheet of Doom plus `./investigations/<investigation_id>/wiki/`.
- Separate exact atomic indicators from broader adversary-tracking patterns.
- Preserve TI placeholders for later VT or external enrichment.

### 11. VirusTotal

Path: `skills/virustotal/`

Purpose:

- Enrich hashes, URLs, domains, and IPs with VirusTotal from a repo-local
  Python CLI.
- Mirror the referenced `mcp-virustotal` tool surface with report and
  relationship commands.
- Resolve the API key from `VIRUSTOTAL_API_KEY` first, then fall back to
  `./config.json`.
- Save durable VT outputs under `./investigations/<investigation_id>/evidence/virustotal/`
- Default file-report output is a compact analyst summary with file link,
  details, and telemetry; URL, IP, and domain reports now follow the same
  compact-summary pattern. Use `-raw` / `--raw` for the full VT payload
  for later wiki and IOC-tracker use.

Example:

```bash
mkdir -p ./investigations/shieldbase-intrusion/evidence/virustotal
python3 ./skills/virustotal/scripts/virustotal_cli.py list_tools
python3 ./skills/virustotal/scripts/virustotal_cli.py get_file_report --hash 87c8fa606729ed63cb9d59f6b731338f8b06addbb3ef91e99b773eac2f2c524d --output ./investigations/shieldbase-intrusion/evidence/virustotal/base-dc-subject-srv-file-report.json
python3 ./skills/virustotal/scripts/virustotal_cli.py get_file_report --hash 87c8fa606729ed63cb9d59f6b731338f8b06addbb3ef91e99b773eac2f2c524d -raw --output ./investigations/shieldbase-intrusion/evidence/virustotal/base-dc-subject-srv-file-report.raw.json
```

Examples:

```bash
mkdir -p ./volatility3-cache ./investigations/shieldbase-intrusion/evidence/systems/base-dc/volatility3/dumps
./skills/investigation/scripts/init_investigation.sh shieldbase-intrusion
cd /Users/matt/git/dfir-skills && ./venv/bin/python ./volatility3/vol.py -f ./data/base-dc-memory.img --offline --cache-path ./volatility3-cache -r pretty windows.psscan > ./investigations/shieldbase-intrusion/evidence/systems/base-dc/volatility3/windows.psscan.txt
cd /Users/matt/git/dfir-skills && ./venv/bin/python ./volatility3/vol.py -f ./data/base-dc-memory.img --offline --cache-path ./volatility3-cache -vvv windows.psscan > ./investigations/shieldbase-intrusion/evidence/systems/base-dc/volatility3/windows.psscan.vvv.txt 2> ./investigations/shieldbase-intrusion/evidence/systems/base-dc/volatility3/windows.psscan.vvv.err
./skills/investigation-ingest/scripts/sync_investigation.sh shieldbase-intrusion
```

## Notes

- `SKILL.md` files describe when and how to use each skill.
- Only create a `scripts/` subfolder when the skill needs executable helpers.
  Command-first skills can keep their canonical workflow directly in
  `SKILL.md`.
- Root repo defaults and execution guidance live in `config.md`, `agents.md`,
  and `requirements.txt`.
