# Configuration Defaults

## Paths

| Setting | Default |
|---|---|
| Analysis folder | `~/data` |
| Velociraptor folder | `~/velociraptor` |
| Repo virtualenv | `./venv` |
| Repo tool staging | repo root |

## Usage

- Use `~/data` as the default analysis and data workspace for case material, evidence,
  and investigation outputs unless the user specifies a different location.
- Use `~/velociraptor` as the default folder for Velociraptor binaries,
  configuration, and related artefacts unless the user specifies a different
  location.
- Use '~/volatility3' as the default volatility folder
- When working from the repo-managed default staging layout, use the repo root
  as the tool staging area and run Velociraptor from `./velociraptor`.
- Use `--datastore=.` in the Velociraptor workspace so local server state stays
  inside that folder.
- Use the repo-local `./venv` as the default Python virtual environment for
  validation, helper tooling, and skill-managed dependency installs.
