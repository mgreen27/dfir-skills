---
name: windows-registry-analysis
description: Run Windows.Registry.Hunter through the local Velociraptor API for dead-disk registry analysis, with RemappingStrategy set to None and results fetched from the Results scope. Use when you need broad registry triage, want to split Registry Hunter by category groups, or need durable Results-scope output for investigation review.
---

# Windows Registry Analysis

Use this skill for large registry-focused Velociraptor collections against a
mapped Windows image. The critical requirement is:

- run `Windows.Registry.Hunter` with `RemappingStrategy='None'`

This is not optional for this workflow. For this repo, the host remap already
provides the registry view, so this skill disables the artifact's internal
remapping logic and reads from the artifact's `Results` scope.

## Workflow

1. Confirm the repo-local Velociraptor workspace exists under `./velociraptor`.
2. Confirm the target client is online and has a recent `LastSeen`.
3. Review prior `Windows.Registry.Hunter` flows before queueing another run.
4. Create or reuse an output folder under:
   `./investigations/<investigation_id>/evidence/systems/<hostname>/velociraptor/registry-hunter/`
5. Prefer split collection waves instead of collecting every category at once.
6. Fetch `Windows.Registry.Hunter/Results` as the main review output.
7. Sync the investigation wiki after saving the raw outputs.

## Category Sets

Use these exact category groups as the default split.

System-information wave:

```json
["Antivirus","Cloud Storage","Devices","Installed Software","Microsoft Exchange","Microsoft Office","Network Shares","System Info","User Accounts","Web Browsers"]
```

Investigation-specific wave:

```json
["ASEP","ASEP Classes","Autoruns","Event Logs","Persistence","Program Execution","Services","Third Party Applications","Threat Hunting","User Activity","Volume Shadow Copies"]
```

Full category set, only when explicitly needed:

```json
["ASEP","ASEP Classes","Antivirus","Autoruns","Cloud Storage","Devices","Event Logs","Installed Software","Microsoft Exchange","Microsoft Office","Network Shares","Persistence","Program Execution","Services","System Info","Third Party Applications","Threat Hunting","User Accounts","User Activity","Volume Shadow Copies","Web Browsers"]
```

## Commands

Confirm the target client is online:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --runas api \
  query --format json \
  "SELECT client_id, os_info.hostname as Hostname, timestamp(epoch=last_seen_at) as LastSeen FROM clients() WHERE os_info.hostname =~ '^base-file$' OR os_info.fqdn =~ '^base-file$' ORDER BY LastSeen DESC LIMIT 1"
```

Review prior Registry Hunter flows, newest first:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --runas api \
  query --format json \
  "SELECT session_id, timestamp(epoch=create_time) as Created, state, total_collected_rows, request.specs[0].artifact as ArtifactName, request.specs[0].parameters.env as Params FROM flows(client_id='C.7c663bb1358359cf') WHERE request.specs[0].artifact = 'Windows.Registry.Hunter' ORDER BY create_time DESC"
```

Create the output folder:

```bash
mkdir -p /Users/matt/git/dfir-skills/investigations/shieldbase-intrusion/evidence/systems/base-file/velociraptor/registry-hunter
```

Run the system-information wave:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --definitions /Users/matt/git/dfir-skills/velociraptor/artifact_definitions \
  --runas api \
  artifacts collect Windows.Registry.Hunter \
  --client_id C.7c663bb1358359cf \
  --org_id root \
  --args RemappingStrategy='None' \
  --args Categories='["Antivirus","Cloud Storage","Devices","Installed Software","Microsoft Exchange","Microsoft Office","Network Shares","System Info","User Accounts","Web Browsers"]'
```

Run the investigation-specific wave:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --definitions /Users/matt/git/dfir-skills/velociraptor/artifact_definitions \
  --runas api \
  artifacts collect Windows.Registry.Hunter \
  --client_id C.7c663bb1358359cf \
  --org_id root \
  --args RemappingStrategy='None' \
  --args Categories='["ASEP","ASEP Classes","Autoruns","Event Logs","Persistence","Program Execution","Services","Third Party Applications","Threat Hunting","User Activity","Volume Shadow Copies"]'
```

Fetch the main result scope:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --runas api \
  query --format jsonl \
  "SELECT * FROM source(client_id='C.7c663bb1358359cf', flow_id='F.<flow_id>', artifact='Windows.Registry.Hunter/Results')" \
  > /Users/matt/git/dfir-skills/investigations/shieldbase-intrusion/evidence/systems/base-file/velociraptor/registry-hunter/base-file-registry-hunter-results.jsonl
```

Fetch the supporting scopes when needed:

```bash
cd /Users/matt/git/dfir-skills/velociraptor
./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --runas api \
  query --format jsonl \
  "SELECT * FROM source(client_id='C.7c663bb1358359cf', flow_id='F.<flow_id>', artifact='Windows.Registry.Hunter/Rules')" \
  > /Users/matt/git/dfir-skills/investigations/shieldbase-intrusion/evidence/systems/base-file/velociraptor/registry-hunter/base-file-registry-hunter-rules.jsonl

./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --runas api \
  query --format jsonl \
  "SELECT * FROM source(client_id='C.7c663bb1358359cf', flow_id='F.<flow_id>', artifact='Windows.Registry.Hunter/Globs')" \
  > /Users/matt/git/dfir-skills/investigations/shieldbase-intrusion/evidence/systems/base-file/velociraptor/registry-hunter/base-file-registry-hunter-globs.jsonl

./velociraptor -a /Users/matt/git/dfir-skills/velociraptor/api_client.yaml \
  --runas api \
  query --format jsonl \
  "SELECT * FROM source(client_id='C.7c663bb1358359cf', flow_id='F.<flow_id>', artifact='Windows.Registry.Hunter/Remapping')" \
  > /Users/matt/git/dfir-skills/investigations/shieldbase-intrusion/evidence/systems/base-file/velociraptor/registry-hunter/base-file-registry-hunter-remapping.jsonl
```

Sync the investigation after the outputs land:

```bash
./skills/investigation-ingest/scripts/sync_investigation.sh shieldbase-intrusion
```

## Notes

- Treat `RemappingStrategy='None'` as a hard requirement for this skill.
- The main analyst review scope is `Results`.
- `Rules`, `Globs`, and `Remapping` are support scopes for troubleshooting and
  interpretation.
- Prefer split category waves to keep output sizes reviewable and easier to
  chunk into the investigation wiki.
