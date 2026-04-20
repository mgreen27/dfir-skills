---
name: prep-dfir-tools
description: Prepare common DFIR tooling on macOS or Linux hosts. Use when you need to bootstrap or stage Velociraptor, Volatility 3, Sleuth Kit, and the repo-local Python environment for a DFIR workstation, lab host, or investigation environment.
---

# Prep DFIR Tools

Run `scripts/prep_dfir_tools.sh` to prepare supported DFIR tooling for the
current macOS or Linux host.

## Workflow

1. Let the script create or reuse the repo-local `./venv`.
2. Choose a destination directory and tool scope.
3. Run `scripts/prep_dfir_tools.sh` with `-d` and `-t` as needed.
4. Review any follow-up install steps printed by the script.

## Commands

Run from the repo root:

```bash
./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh
```

Stage tools into a custom directory:

```bash
./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -d /opt/dfir
```

Refresh only the repo virtual environment and root requirements:

```bash
./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t venv
```

Prepare a single tool:

```bash
./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t velociraptor
./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t volatility
./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t tsk
```

## Velociraptor

The Velociraptor binary is staged under a dedicated folder:

```text
./velociraptor/velociraptor
```

During prep, the script automatically:

- starts `./velociraptor gui -v --datastore=. --nobrowser --noclient`
- waits up to 10 seconds for the workspace config to appear
- generates `server.config.yaml`, local datastore files, and `api_client.yaml`
- runs `Server.Import.Extras`, `Server.Import.ArtifactExchange`, and
  `Server.Import.DetectRaptor` through `api_client.yaml` as the `api` user
  while the temporary server is still running
- stops it
- removes the default sample tenant block so the workspace stays root-only

Run Velociraptor from that folder when working in local GUI mode so
`--datastore=.` writes into the Velociraptor workspace:

```bash
cd velociraptor
./velociraptor gui -v --datastore=. --nobrowser --noclient
```

After the local workspace is initialized, generate an API client config with:

```bash
./velociraptor config api_client --name api --role administrator api_client.yaml
```

## Notes

- Detect the local operating system and CPU architecture automatically.
- Create and reuse the repo-local virtual environment at `./venv`.
- Install root `requirements.txt` into `./venv` when possible.
- Support `-t venv` for granular refresh of just the repo-local Python
  environment.
- Install the official Velociraptor Python client from the root requirements so
  the repo venv is ready for later API automation.
- Stage tools in the repo root by default, including Velociraptor under
  `./velociraptor/`.
- Keep Velociraptor runtime files alongside the binary when using
  `--datastore=.`.
- Initialize the Velociraptor workspace automatically during prep by running
  local GUI mode, generating `api_client.yaml`, and importing
  `Server.Import.Extras`, `Server.Import.ArtifactExchange`, and
  `Server.Import.DetectRaptor` before stopping the temporary server.
- Keep the default Velociraptor workspace root-only rather than creating sample
  extra tenants.
- Require outbound HTTPS access during Velociraptor prep when importing
  community artifacts into the local workspace.
- Install Sleuth Kit with Homebrew on macOS when `brew` is available.
- Download Sleuth Kit source on Linux or on macOS hosts without Homebrew.
- Install Volatility 3 `full`, `cloud`, and `arrow` extras into `./venv` when
  possible.
