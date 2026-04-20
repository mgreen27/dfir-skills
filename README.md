# dfir-skills

A small DFIR skills repository for automated incident response. Each skill lives
in its own folder and contains a `SKILL.md` plus a `scripts/` subfolder.

The repo assumes a local Python virtual environment at `./venv`. The prep skill
can create and populate that environment automatically.
Tool prep stages tools in the repo root by default.

## Repository Layout

```text
skills/
  add-velociraptor-mapped-client/
    SKILL.md
    scripts/
      add_mapped_client.sh
  windows_analysis/
    SKILL.md
    scripts/
  prep-dfir-tools/
    SKILL.md
    scripts/
      prep_dfir_tools.sh
  detect-dfir-collection-type/
    SKILL.md
    scripts/
      detect_collection.py
```

## Skills

### 1. Prep DFIR Tools

Path: `skills/prep-dfir-tools/`

Purpose:

- Prepare common DFIR tools for macOS and Linux hosts.
- Supports Velociraptor, Volatility 3, and Sleuth Kit.
- Bootstraps the repo-local `./venv` automatically when Python is available.
- Installs Python support for the Velociraptor API and broader Volatility 3
  plugin coverage during prep.

Run:

```bash
./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh
```

Examples:

```bash
./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -d /opt/dfir
./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t venv
./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t velociraptor
```

Velociraptor runtime pattern:

```bash
cd velociraptor
./velociraptor gui -v --datastore=. --nobrowser --noclient
./velociraptor config api_client --name api --role administrator api_client.yaml
```

The prep script now bootstraps that workspace automatically by starting local
GUI mode, waiting up to 10 seconds for the workspace config, generating
`api_client.yaml`, and importing `Server.Import.Extras`,
`Server.Import.ArtifactExchange`, and `Server.Import.DetectRaptor` through the
API user before stopping the temporary server.
It also removes the default sample tenant block so the local workspace stays on
the root org only. Outbound HTTPS access is required for the extra artifact
import step.

### 2. Add Velociraptor Mapped Client

Path: `skills/add-velociraptor-mapped-client/`

Purpose:

- Reuse or start the local Velociraptor GUI workspace.
- Generate a dead-disk remapping for an offline Windows image or mounted
  Windows directory.
- Launch a background mapped client so the evidence appears in GUI mode.
- Derive the mapped client hostname from the image or folder name unless `-n`
  is provided explicitly.

Run:

```bash
./skills/add-velociraptor-mapped-client/scripts/add_mapped_client.sh /path/to/image.E01
```

Examples:

```bash
./skills/add-velociraptor-mapped-client/scripts/add_mapped_client.sh /cases/host01.E01
./skills/add-velociraptor-mapped-client/scripts/add_mapped_client.sh -n dead-disk-lab01 /mnt/windows
```

Each mapped client gets its own `client.config.yaml` and writeback file under
`./velociraptor/mapped-clients/<name>/` so the displayed hostname remains tied
to that image or folder instead of reusing a shared client identity.
The mapped-client workspace now records API-queried client metadata in
`client-info.json` and references that file from `session.env`.

### 3. Detect DFIR Collection Type

Path: `skills/detect-dfir-collection-type/`

Purpose:

- Detect whether a path contains a disk image, memory image, process dump,
  live-response collection, mixed folder, or an unknown artefact set.

Run:

```bash
python3 ./skills/detect-dfir-collection-type/scripts/detect_collection.py /path/to/evidence
```

Examples:

```bash
python3 ./skills/detect-dfir-collection-type/scripts/detect_collection.py -v /cases/case001
python3 ./skills/detect-dfir-collection-type/scripts/detect_collection.py --json /evidence
```

### 4. Windows Analysis

Path: `skills/windows_analysis/`

Purpose:

- Run Windows-focused analysis artifacts through the local Velociraptor API.
- List available Windows and DetectRaptor artifacts before broader collections.
- Confirm the target client is online before queueing analysis.
- Check for an existing matching collection before queueing the same artifact
  and parameter set again.
- Write collection outputs into the machine investigation folder and keep both
  `investigation-notes.md` and `investigation-results.md` beside them.
- Treat unbounded `flows()` review as a critical requirement before analysis.
- Run bounded Windows triage and follow-up collections against a mapped or live
  Windows client, including `DetectRaptor.Windows.Detection.Evtx`,
  `DetectRaptor.Windows.Detection.Applications`,
  `DetectRaptor.Windows.Detection.Powershell.PSReadline`,
  `Windows.Detection.Amcache`, `Windows.Forensics.Bam`,
  `Windows.Forensics.Timeline`, `Windows.Registry.UserAssist`,
  `Windows.Registry.AppCompatCache`, `Windows.Forensics.Prefetch`,
  `Windows.NTFS.MFT`, `Windows.Search.FileFinder`,
  `DetectRaptor.Generic.Detection.YaraFile`,
  `DetectRaptor.Generic.Detection.YaraWebshell`, and
  `DetectRaptor.Generic.Detection.BrowserExtensions`.

Run:

```bash
cd ./velociraptor
./velociraptor --config ./server.config.yaml artifacts show DetectRaptor.Windows.Detection.Evtx
```

Examples:

```bash
cd ./velociraptor && ./velociraptor --config ./server.config.yaml artifacts list '^DetectRaptor\.Windows\.|^Windows\.'
cd ./velociraptor && ./velociraptor -a ./api_client.yaml --runas api query --format json "SELECT client_id, os_info.hostname as Hostname, timestamp(epoch=last_seen_at) as LastSeen FROM clients() WHERE os_info.hostname =~ '^base-dc$' ORDER BY LastSeen DESC LIMIT 1"
cd ./velociraptor && ./velociraptor -a ./api_client.yaml --runas api query --format json "SELECT session_id, timestamp(epoch=create_time) as Created, state, total_collected_rows, artifacts_with_results, request.specs[0].artifact as ArtifactName FROM flows(client_id='C.6d94a75e45cb9367') ORDER BY create_time DESC"
mkdir -p ./investigations/base-dc/velociraptor && touch ./investigations/base-dc/investigation-notes.md ./investigations/base-dc/investigation-results.md
cd ./velociraptor && ./velociraptor -a ./api_client.yaml --definitions ./artifact_definitions --runas api artifacts collect DetectRaptor.Windows.Detection.Evtx --client_id C.6d94a75e45cb9367 --org_id root
cd ./velociraptor && ./velociraptor -a ./api_client.yaml --runas api query --format jsonl "SELECT * FROM source(client_id='C.6d94a75e45cb9367', flow_id='F.D7IRINBEJ3OVI', artifact='DetectRaptor.Windows.Detection.Evtx')" > ./investigations/base-dc/velociraptor/base-dc-detectraptor-evtx.jsonl
```

Collections should be written into a reusable investigation folder under
`./investigations/<investigation-name>/velociraptor/`, with a sibling
`investigation-notes.md` file for running context and analyst notes, plus an
`investigation-results.md` file for the actual DFIR findings summary.

Check `LastSeen` before collecting. If the client is not online, API-scheduled
collections will stay queued and nothing useful will appear in the GUI.

Start prior-run review with a latest-first `flows()` query that includes
readable timestamps, then narrow to an exact artifact-and-parameter match if
needed. This query should not use `LIMIT`; truncating the flow inventory is a
bad default for investigations.

Before starting a new collection, query `flows()` for the same artifact and
parameter set so you can reuse an earlier result instead of queueing a
duplicate run.

Unless the user explicitly asks for a bounded time window, do not add date
limits to the collection command.

Prefer retrieving finished collection rows through the API with
`source(client_id=..., flow_id=..., artifact=...)` and saving the results as
`jsonl` in the investigation folder. Small outputs can still be saved as
single JSON documents, but `jsonl` is the safer default for larger flows.
Only use `--output ...zip` when you explicitly need the full Velociraptor
package.

For evidence-of-execution artifacts, review the artifact description with
`artifacts show <name>` before drawing conclusions. Several of these artifacts
have important interpretation caveats and should not be treated as equivalent
execution proof.

## Notes

- `SKILL.md` files describe when and how to use each skill.
- Skills keep a `scripts/` subfolder available, but simple workflows may define
  their canonical commands directly in `SKILL.md` when that is clearer than a
  wrapper script.
- Root repo defaults and execution guidance live in `config.md`, `agents.md`,
  and `requirements.txt`.
