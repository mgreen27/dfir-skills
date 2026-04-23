# Configuration Defaults

## Paths

| Setting | Default |
|---|---|
| Analysis folder | `~/data` |
| Investigation root | `./investigations` |
| Investigation wiki folder | `./investigations/<investigation_id>/wiki` |
| Spreadsheet of Doom root | `./investigations/<investigation_id>/spreadsheet-of-doom` |
| Evidence root | `./investigations/<investigation_id>/evidence` |
| Velociraptor folder | `~/velociraptor` |
| Velociraptor program file | `./velociraptor/velociraptor` |
| Repo virtualenv | `./venv` |
| Repo tool staging | repo root |
| VirusTotal config | `./virustotal-config.json` |

## Usage

- Use `~/data` as the default analysis and data workspace for case material
  and evidence unless the user specifies a different location.
- Use `./investigations` under the repo root for saved investigation folders.
- Structure each case as:
  `./investigations/<investigation_id>/{wiki,spreadsheet-of-doom,evidence}`.
- Use `./investigations/<investigation_id>/spreadsheet-of-doom` for the
  canonical structured case record.
- Use `./investigations/<investigation_id>/evidence/systems/<system>/` for
  raw per-system outputs that belong to the same investigation.
- Use `./investigations/<investigation_id>/wiki/` for investigation-centric
  markdown that holds iterative analysis, questions, and artifact notes.
- Write `<investigation_id>_SoD.xlsx` into the investigation root for
  analyst-friendly reading after each sync.
- Use `~/velociraptor` as the default folder for Velociraptor binaries,
  configuration, and related artefacts unless the user specifies a different
  location.
- Use '~/volatility3' as the default volatility folder
- When working from the repo-managed default staging layout, use the repo root
  as the tool staging area and run Velociraptor from `./velociraptor`.
- Use `./velociraptor/velociraptor` as the default repo-local Velociraptor
  program file when a skill needs the binary path explicitly.
- Use `--datastore=.` in the Velociraptor workspace so local server state stays
  inside that folder.
- Use the repo-local `./venv` as the default Python virtual environment for
  validation, helper tooling, and skill-managed dependency installs.
- Use `VIRUSTOTAL_API_KEY` as the first-choice VirusTotal credential source,
  and fall back to the repo-local `./virustotal-config.json` when a skill
  needs a saved local API key.
