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

## Notes

- `SKILL.md` files describe when and how to use each skill.
- The executable logic for each skill lives only under that skill's `scripts/`
  directory.
- Root repo defaults and execution guidance live in `config.md`, `agents.md`,
  and `requirements.txt`.
