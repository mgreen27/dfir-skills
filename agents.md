# Agents Guide

## Purpose

This skills repository exists to enable automated incident response workflows.
Agents operating in this repo should prefer repeatable, script-backed DFIR tasks
that help prepare tooling, classify evidence, and support downstream analysis.

## Operating Rules

1. Keep the repo focused on automated incident response use cases.
2. Maintain each skill as a separate folder with a `SKILL.md` and a `scripts/`
   subfolder.
3. Read [config.md](./config.md) before adding defaults or path assumptions.
4. Assume the repo-local virtual environment lives at `./venv` unless the user
   says otherwise.
5. Prefer repo scripts that can create and reuse `./venv` automatically.
6. If you add a new Python-backed capability, helper, or validation workflow,
   update the root `requirements.txt`.
7. Keep `prep_dfir_tools.sh` modular so agents can refresh only the required
   component, such as `./venv`, instead of rerunning every prep step.
8. Update the `Execution Learnings` section in this file after each execution.
9. Keep learnings short, dated, and directly useful to the next agent run.

## Execution Learnings

### 2026-04-17

- Repo purpose was formalized around automated incident response.
- Root config defaults are `~/cases` for analysis and `~/velociraptor` for
  Velociraptor data and tooling.
- Root `requirements.txt` now includes `PyYAML` so skill validation tooling can
  run in a prepared environment.
- Current skills are `prep-dfir-tools` and `detect-dfir-collection-type`.
- Repo automation now assumes a local virtual environment at `./venv`.
- The prep skill is responsible for creating `./venv` and installing root
  Python requirements into it when Python is available.
- The tooling-preparation skill was renamed from `download-dfir-tools` to
  `prep-dfir-tools` so the name reflects both dependency bootstrap and tool
  staging.
- The repo-local virtual environment was created at `./venv` and the current
  root requirements were installed successfully.
- Repo policy now requires agents to update `requirements.txt` when they add a
  new Python-backed capability or helper.
- The prep skill should stay modular so components like `./venv` can be
  refreshed independently.
- The repo-local `venv/` directory is intentionally gitignored and should not
  be committed.
- `prep_dfir_tools.sh -t venv` now provides a granular way to refresh just the
  repo virtual environment and root requirements.
- Velociraptor release assets must be resolved from current GitHub release
  metadata because the asset version suffix can differ from the release tag.
- Volatility 3 should be installed from its current package metadata
  (`pyproject.toml` and `.[full]`) when a top-level `requirements.txt` is not
  present.
- Volatility 3 writes cache data under `~/.cache/volatility3` by default, so
  sandboxed verification may require `XDG_CACHE_HOME` or `--cache-path` to
  point at a writable workspace path.
- Root requirements now include the official `pyvelociraptor` client so the
  repo venv is ready for later Velociraptor API automation.
- Tool prep should install Volatility 3 `full`, `cloud`, and `arrow` extras so
  remote-storage and Arrow/Parquet-capable workflows are available after prep.
- On Python 3.14, `pyvelociraptor` currently pins `grpcio==1.73.0`, while the
  `gcsfs` dependency chain can pull packages that want newer gRPC; imports may
  still work, but `pip check` is not clean in a single shared venv.
- Velociraptor should be staged and operated from a dedicated workspace folder
  such as `dfir-tools/velociraptor/`, with `./velociraptor gui -v --datastore=. --nobrowser --noclient`
  run from inside that folder so runtime state stays local.
- An initial `gui` launch generates `server.config.yaml`, `client.config.yaml`,
  datastore folders, and an admin user in the Velociraptor workspace.
- API client configs can be generated directly from the workspace config with
  `./velociraptor config api_client --name api --role administrator api_client.yaml`.
- Default tool staging now lives at the repo root, with top-level tool folders
  such as `./velociraptor/` and `./volatility3/`.
- Velociraptor prep should initialize the local workspace automatically by
  running `gui -v --datastore=. --nobrowser --noclient` for 10 seconds, then
  stopping it and generating `api_client.yaml`.
- Before attempting dead-disk remapping, verify the evidence path is a real
  image and not a placeholder or stub file; the current `data/base-dc-cdrive.E01`
  in this worktree is only a 17-byte text file and cannot be mounted.
- The repo now includes a dedicated skill to attach a dead-disk image or
  mounted Windows directory as a background Velociraptor mapped client, reusing
  the local GUI instance when it is already reachable and starting it only when
  needed.
- In this macOS sandbox, loopback HTTPS checks to the Velociraptor GUI can fail
  even when `lsof` shows the GUI and API listeners are already up, so listener
  checks are more reliable than `curl` alone for scripted GUI-state detection.
- In this sandbox, a background dead-disk client may stay running while failing
  to register with the local frontend because loopback connects to
  `https://localhost:8000/` can return `operation not permitted`; treat that as
  an environment restriction, not a dead-disk remapping failure.

### 2026-04-19

- The mapped-client skill successfully attached `data/base-dc-cdrive.E01` as a
  Velociraptor dead-disk client using the hostname `base-dc-cdrive`, and the
  local client established frontend connections on `127.0.0.1:8000`.

### 2026-04-20

- The mapped-client skill now generates a per-client `client.config.yaml` and
  writeback file under `velociraptor/mapped-clients/<name>/` so the hostname
  derived from the image or folder name maps to a stable Velociraptor client
  identity instead of reusing the shared workspace writeback.
- When rebuilding the Velociraptor workspace from scratch, stop any live GUI
  process before deleting `./velociraptor/`, rerun `prep_dfir_tools.sh -t
  velociraptor`, and then reattach dead-disk clients against the fresh
  workspace.
- The mapped-client skill now defaults the hostname to the exact image or
  folder basename, without the old `dead-disk-` prefix.
- Velociraptor prep now strips the default sample tenant block from
  `server.config.yaml` and removes `orgs/O123*`, so rebuilt workspaces stay
  root-only unless the user explicitly adds tenants later.
- For reliable local analysis in this environment, keep the Velociraptor GUI
  server and the mapped dead-disk client running in separate live sessions
  instead of relying on short-lived background jobs.
- `Server.Import.Extras` works against the local root org when invoked through
  `api_client.yaml` with `--runas api`, and prep should run that import before
  the temporary initialization server is stopped.
- Velociraptor community artifact import requires outbound HTTPS access during
  prep; when it fails, leave a warning and keep the local workspace usable.
- `Server.Import.DetectRaptor` is not built in by default; prep must first run
  `Server.Import.ArtifactExchange`, then collect `Server.Import.DetectRaptor`
  as the `api` user against the root org.
