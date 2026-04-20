# dfir-skills

A DFIR skills repository for automated incident response and iterative analysis.
Each skill lives in its own folder and contains a `SKILL.md`. A `scripts/`
subfolder is only needed when the skill actually ships executable helpers.

The repo assumes a local Python virtual environment at `./venv`. Tool prep
stages tools in the repo root by default.

## Operating Model

- Raw DFIR outputs live under `./investigations/<hostname>/`.
- Iterative analyst reasoning lives in an Obsidian vault under
  `./investigation-wikis/<hostname>/`.
- Velociraptor runs from `./velociraptor/`.
- Volatility 3 runs from `./volatility3/`.

## Repository Layout

```text
skills/
  prep-dfir-tools/
  add-velociraptor-mapped-client/
  detect-dfir-collection-type/
  investigation-wiki/
  investigation-wiki-ingest/
  investigation-wiki-query/
  windows_analysis/
  memory-analysis/
```

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

### 2. Add Velociraptor Mapped Client

Path: `skills/add-velociraptor-mapped-client/`

Purpose:

- Reuse or start the local Velociraptor GUI workspace.
- Generate a dead-disk remapping for an offline Windows image or mounted
  Windows directory.
- Launch a background mapped client so the evidence appears in GUI mode.
- Derive the mapped client hostname from the image or folder name.

Run:

```bash
./skills/add-velociraptor-mapped-client/scripts/add_mapped_client.sh /path/to/image.E01
```

### 3. Detect DFIR Collection Type

Path: `skills/detect-dfir-collection-type/`

Purpose:

- Detect whether a path contains a disk image, memory image, process dump,
  live-response collection, mixed folder, or an unknown artefact set.

Run:

```bash
python3 ./skills/detect-dfir-collection-type/scripts/detect_collection.py /path/to/evidence
```

### 4. Investigation Wiki

Path: `skills/investigation-wiki/`

Purpose:

- Scaffold a per-host Obsidian vault for iterative DFIR analysis.
- Keep findings, leads, timeline, and evidence notes separate from raw tool
  outputs.
- Provide a standard case layout that can be refreshed over multiple analysis
  passes.

Run:

```bash
./skills/investigation-wiki/scripts/init_investigation_wiki.sh base-dc
```

### 5. Investigation Wiki Ingest

Path: `skills/investigation-wiki-ingest/`

Purpose:

- Sync raw case outputs from `./investigations/<hostname>/` into the host
  Obsidian vault.
- Build file-level artifact notes under `wiki/artifacts/`.
- Refresh the case hot cache and sync status.
- Migrate legacy `investigation-notes.md` and `investigation-results.md` into
  the vault when they still exist.

Run:

```bash
./skills/investigation-wiki-ingest/scripts/sync_investigation_wiki.sh base-dc
```

### 6. Investigation Wiki Query

Path: `skills/investigation-wiki-query/`

Purpose:

- Answer case questions from the per-host investigation wiki.
- Prefer the accumulated analysis in `wiki/hot.md`, `wiki/findings.md`,
  `wiki/leads.md`, and `wiki/timeline.md` before reopening raw files.

### 7. Windows Analysis

Path: `skills/windows_analysis/`

Purpose:

- Run Windows-focused Velociraptor analysis artifacts through the local API.
- Confirm the target client is online before queueing analysis.
- Check for an existing matching collection before queueing the same artifact
  and parameter set again.
- Write collection outputs into `./investigations/<hostname>/velociraptor/`.
- Keep iterative analysis in the host's Obsidian vault under
  `./investigation-wikis/<hostname>/`.
- Treat unbounded `flows()` review as a critical requirement before analysis.

Examples:

```bash
./skills/investigation-wiki/scripts/init_investigation_wiki.sh base-dc
mkdir -p ./investigations/base-dc/velociraptor
cd ./velociraptor && ./velociraptor -a ./api_client.yaml --runas api query --format json "SELECT session_id, timestamp(epoch=create_time) as Created, state, total_collected_rows, artifacts_with_results, request.specs[0].artifact as ArtifactName FROM flows(client_id='C.6d94a75e45cb9367') ORDER BY create_time DESC"
cd ./velociraptor && ./velociraptor -a ./api_client.yaml --definitions ./artifact_definitions --runas api artifacts collect DetectRaptor.Windows.Detection.Evtx --client_id C.6d94a75e45cb9367 --org_id root
cd ./velociraptor && ./velociraptor -a ./api_client.yaml --runas api query --format jsonl "SELECT * FROM source(client_id='C.6d94a75e45cb9367', flow_id='F.D7IRINBEJ3OVI', artifact='DetectRaptor.Windows.Detection.Evtx')" > ./investigations/base-dc/velociraptor/base-dc-detectraptor-evtx.jsonl
./skills/investigation-wiki-ingest/scripts/sync_investigation_wiki.sh base-dc
```

### 8. Memory Analysis

Path: `skills/memory-analysis/`

Purpose:

- Run Volatility 3 triage against a Windows memory image with repo-local
  tooling.
- Write text outputs into `./investigations/<hostname>/volatility3/`.
- Keep iterative analysis in the host's Obsidian vault instead of flat case
  markdown files.
- Use scan-based plugins and `-vvv` diagnostics when richer plugins fail.

Examples:

```bash
mkdir -p ./volatility3-cache ./investigations/base-dc/volatility3/dumps
./skills/investigation-wiki/scripts/init_investigation_wiki.sh base-dc
cd /Users/matt/git/dfir-skills && ./venv/bin/python ./volatility3/vol.py -f ./data/base-dc-memory.img --offline --cache-path ./volatility3-cache -r pretty windows.psscan > ./investigations/base-dc/volatility3/windows.psscan.txt
cd /Users/matt/git/dfir-skills && ./venv/bin/python ./volatility3/vol.py -f ./data/base-dc-memory.img --offline --cache-path ./volatility3-cache -vvv windows.psscan > ./investigations/base-dc/volatility3/windows.psscan.vvv.txt 2> ./investigations/base-dc/volatility3/windows.psscan.vvv.err
./skills/investigation-wiki-ingest/scripts/sync_investigation_wiki.sh base-dc
```

## Notes

- `SKILL.md` files describe when and how to use each skill.
- Only create a `scripts/` subfolder when the skill needs executable helpers.
  Command-first skills can keep their canonical workflow directly in
  `SKILL.md`.
- Root repo defaults and execution guidance live in `config.md`, `agents.md`,
  and `requirements.txt`.
