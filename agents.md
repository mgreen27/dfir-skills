# Agents Guide

## Purpose

This skills repository exists to enable automated incident response workflows.
Agents operating in this repo should prefer repeatable, script-backed DFIR tasks
that help prepare tooling, classify evidence, and support downstream analysis.

## Operating Rules

1. Keep the repo focused on automated incident response use cases.
2. Maintain each skill as a separate folder with a `SKILL.md`. Add a
   `scripts/` subfolder only when the skill actually needs executable helpers.
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
10. Treat the unbounded `flows()` inventory query as a critical investigation
    requirement. Do not add `LIMIT` to the canonical prior-flow review query.
11. Treat `./investigations/<investigation_id>/wiki/` as the default durable
    narrative analysis record for iterative casework.
12. Treat `./investigations/<investigation_id>/spreadsheet-of-doom/` as the
    canonical structured case record for the investigation.
13. Keep raw tool outputs under
    `./investigations/<investigation_id>/evidence/systems/<system>/` and use
    the investigation wiki plus Spreadsheet of Doom for iterative review.
14. Refresh the Spreadsheet of Doom CSVs first, then regenerate the
    root-level `<investigation_id>_SoD.xlsx` workbook.
15. The default analysis objective is a full DFIR review of the provided
    evidence, with explicit highlighting of all potentially malicious
    artifacts before deeper workflow-based review begins.
16. Prefer reviewing existing exported artifact rows before running new
    collections. Recollect only when the user explicitly asks for it or when
    the current exports cannot answer a specific evidence question.

## DFIR Analysis Prompt

Use this prompt when writing investigation analysis or summarizing results:

You are a senior DFIR analyst. Be technically precise, evidence-driven, and
skeptical of weak signals. Review the supplied investigation wiki pages, raw
result files, and artifact outputs with close attention to execution evidence,
timeline consistency, user context, persistence, credential access, lateral
movement, defense evasion, and data staging or exfiltration. Separate
confirmed findings from leads and noise. For each notable item, explain why it
matters, what artifact supports it, how strong the evidence is, and what the
most likely benign explanation would be. Do not overclaim. Call out
interpretation caveats for artifacts like AppCompatCache, UserAssist, Amcache,
BAM, Prefetch, and event-log detections. Produce a concise analyst narrative
with: executive summary, key findings, confidence, gaps, and next
investigative actions. Prefer exact paths, timestamps, usernames, hostnames,
process names, command lines, artifact names, and wiki page references. If
evidence is insufficient, say so clearly.

## Iterative Investigation Prompt

Use this prompt when the goal is to iteratively collect, analyze, and update
the investigation wiki:

You are a senior DFIR analyst working iteratively from two primary evidence
sources: disk analysis through Velociraptor and memory analysis through
Volatility 3. Your job is not only to summarize findings, but to drive the
investigation forward.

Start from the current investigation wiki and the latest raw outputs under
`./investigations/<investigation_id>/`. Read the wiki first to understand the
current analysis, Spreadsheet of Doom status, evidence notes, and open
questions. Review existing exported rows before planning any new collection.
Then decide
whether the next best step is:

1. write or refine analysis in the wiki based on evidence already collected
2. collect additional evidence from Velociraptor disk artifacts
3. collect additional evidence from Volatility memory plugins
4. do both in sequence when the wiki reveals a specific open question that can
   be answered by more collection

When writing to the wiki:
- update `wiki/analysis.md` for confirmed findings, confidence, caveats, and
  next actions
- update the relevant Spreadsheet of Doom CSVs for structured case facts
- update `wiki/hot.md` with the current case position and active threads

When collecting more evidence:
- prefer existing exported artifact rows over recollection whenever those
  exports can answer the current question
- prefer Velociraptor for disk, registry, NTFS, event log, scheduled task, and
  file-presence questions
- prefer Volatility 3 for process, parent-child, command-line, network, and
  memory-resident execution questions
- when iterative analysis narrows a suspicious time window, run a bounded
  post-analysis timeline pivot with `Windows.NTFS.MFT` and
  `Windows.EventLogs.EvtxHunter` using shared `DateAfter` and `DateBefore`
  bounds before broadening collection again
- when a suspicious binary path is identified on disk, run
  `Windows.Detection.BinaryHunter` against the exact path and capture hashes,
  signer details, PE metadata, PDB path, and import-hash information
- check whether equivalent collections already exist before rerunning them
- save all new raw outputs under
  `./investigations/<investigation_id>/evidence/systems/<system>/`
- sync the investigation wiki after new collection results land

Use an explicit loop:
- identify the open question
- choose the best evidence source
- collect only what is needed to answer that question
- update the wiki with what changed
- state the next unresolved question if one remains

Do not treat the wiki as a static report. Treat the investigation wiki plus
Spreadsheet of Doom as the working case file that should both guide collection
and absorb the results of each new analysis step.

## Full DFIR Workflow Prompt

Use this prompt when the goal is a full DFIR analysis of the provided evidence:

You are a senior DFIR analyst performing a full investigation over the
evidence provided for a host or case. Your immediate objective is to identify,
record, and prioritize all potentially malicious artifacts or behaviors across
the main evidence sources:

- disk evidence through Velociraptor
- memory evidence through Volatility 3

Start broad, then narrow:

1. perform an initial full-pass review of the available evidence
2. identify suspicious binaries, persistence mechanisms, credential-access
   indicators, remote-execution artifacts, defense-evasion activity, staging
   paths, suspicious user activity, and timeline anomalies
3. write those items into the investigation wiki and Spreadsheet of Doom as
   potential malicious artifacts, confirmed findings, leads, caveats, and
   timeline events
4. decide which workflow should review each suspicious item more deeply
5. collect more evidence only when needed to answer a specific open question

When running this workflow:
- prefer broad triage first, then targeted pivots
- prefer reviewing completed exports before queueing more collection, unless
  the user explicitly asks for recollection or the current exports do not
  answer the open question
- when timeline anomalies or suspicious windows emerge, use bounded
  `Windows.NTFS.MFT` plus `Windows.EventLogs.EvtxHunter` pivots to look for
  adjacent activity before expanding into broader recollection
- treat suspicious binaries as a standard targeted pivot: use
  `Windows.Detection.BinaryHunter` to turn a path-based lead into a file
  identity record with hashes, signer details, and PE metadata
- highlight all potentially malicious artifacts even when confidence is still
  low
- clearly separate:
  - confirmed malicious findings
  - suspicious leads requiring review
  - benign or explained artifacts
- use the investigation wiki and Spreadsheet of Doom to maintain a durable
  suspicious-artifact and task-review queue that later workflows can consume

The end state of a good first-pass DFIR analysis is not just a narrative. It
is a structured case file that shows:
- what looks malicious
- why it looks suspicious
- what evidence supports it
- what workflow should review it next

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

### 2026-04-20

- On dead-disk Velociraptor clients, exact `Windows.Search.FileFinder` globs
  are an efficient way to validate EVTX hypotheses and can be saved directly as
  durable case `.jsonl` outputs.
- Investigation records can drift behind live collection state; refresh
  `analysis.md`, `spreadsheet-of-doom.md`, and `hot.md` after major
  collection waves rather than relying on the initial scaffold narrative.
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
- Mapped dead-disk clients should be supervised, not launched as a one-shot
  background process. Watch both the local client PID and the API `LastSeen`
  timestamp, and restart stale clients automatically so long-running
  collections do not silently stall when the mapped client exits.
- In the Codex command-runner environment, detached background mapped-client
  supervisors can still be reaped when the launching command exits. For
  durable long-running analysis, run the mapped-client supervisor under a
  host-native service manager such as `launchd` on macOS or `systemd` on
  Linux.
- Registry Hunter output is large enough that the default collection pattern
  should be split into a system-information wave and an
  investigation-specific wave, with results saved under
  `./investigations/<investigation_id>/evidence/systems/<system>/velociraptor/exports/registry-hunter/`.
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
- Velociraptor prep should wait for the local API user to answer a simple query
  before attempting community artifact imports during the temporary init
  window.
- The mapped-client skill should not inspect offline registry hives for host
  metadata; instead it should query `clients()` through `api_client.yaml` and
  treat the `Generic.Client.Info/BasicInformation` record as the source of
  client identity details.
- The repo now includes a `windows-analysis` skill for listing
  Windows/DetectRaptor artifacts and running API-backed collections such as
  `DetectRaptor.Windows.Detection.Evtx` against a hostname or client id.
- Windows-analysis style collections should prefer durable investigation output
  folders under the analysis root when the results are likely to be reviewed in
  multiple passes or chunked for later context management.
- The `windows-analysis` skill is command-first: keep the canonical
  Velociraptor CLI and VQL commands in `SKILL.md` instead of hiding simple
  workflows behind an extra wrapper script.
- The Windows investigation overview should explicitly cover
  `DetectRaptor.Windows.Detection.Applications`,
  `DetectRaptor.Windows.Detection.Powershell.PSReadline`,
  `Windows.Detection.Amcache`, `Windows.Forensics.Bam`,
  `Windows.Forensics.Timeline`, `Windows.Registry.UserAssist`,
  `Windows.Registry.AppCompatCache`, `Windows.Forensics.Prefetch`,
  `Windows.NTFS.MFT`, `Windows.Search.FileFinder`,
  `DetectRaptor.Generic.Detection.YaraFile`,
  `DetectRaptor.Generic.Detection.YaraWebshell`, and
  `DetectRaptor.Generic.Detection.BrowserExtensions` so evidence-of-execution
  and follow-up content-based pivots are documented alongside the initial EVTX
  sweep.
- Evidence-of-execution artifacts must carry interpretation notes or require an
  `artifacts show <name>` review before use; these artifacts do not all provide
  equivalent execution semantics and should not be summarized loosely.
- Windows investigation workflows must check that the target client is online
  and has a recent `LastSeen` before queueing collections. If the mapped client
  is offline, API flows will stay queued and the GUI will not show useful
  results.
- Client collections that should appear in the Velociraptor GUI must be queued
  through `api_client.yaml`; the local `server.config.yaml` path is still
  useful for `artifacts list` and `artifacts show`, but it is not the right
  execution path for GUI-visible client analysis.
- Before queueing a Windows analysis collection, check `flows()` for the same
  artifact and parameter set on the target client. Reuse prior finished results
  where possible instead of creating duplicate collections.
- Prior collection review should start with a latest-first `flows()` query that
  includes readable `Created` and `LastActive` timestamps so the newest runs
  can be triaged before checking for an exact parameter match.
- Windows analysis results should be written under
  `./investigations/<investigation_id>/evidence/systems/<system>/`, while
  iterative analyst work should be captured in the matching investigation
  `wiki/` folder under `./investigations/<investigation_id>/wiki/`.
- Do not add date limits to Windows analysis collections unless the user
  explicitly asks for a bounded time window.
- When queueing DetectRaptor artifacts through the API CLI, pass the local
  `artifact_definitions` directory so the custom artifact names resolve
  correctly.
- For investigation review, prefer API-side result retrieval with
  `source(client_id=..., flow_id=..., artifact=...)` and save JSON into the
  investigation folder. Use `jsonl` as the safe default for larger result
  sets, because the CLI `json` mode may emit multiple JSON arrays in a single
  stream. Only use `--output ...zip` when the user explicitly wants the full
  Velociraptor package.
- The canonical prior-flow inventory query is intentionally unbounded. Do not
  add `LIMIT` to that review step, because truncating the flow list can hide
  the most relevant earlier collections during iterative analysis.
- Investigation folders now live under the repo root at `./investigations/`
  and that path should be gitignored. Use repo-local investigation paths in
  docs, examples, and saved notes instead of `~/data/investigations`.
- If Volatility 3 is run with a repo-local `--cache-path`, create that cache
  directory first. The current CLI will fail immediately if the target cache
  directory does not already exist.
- The repo now includes a `memory-analysis` skill for Volatility 3 triage,
  with outputs written to `./investigations/<investigation-name>/volatility3/`
  and analyst findings maintained in the matching investigation wiki.
- For dead-disk investigations, do not treat Velociraptor mapped clients as
  valid sources for live process semantics. Use the separate memory image and
  Volatility for process, parent-child, and live execution context.
- On the current `base-dc-memory.img`, `windows.info` and `windows.psscan`
  produce useful output, but `pslist`, `cmdline`, `dlllist`, `handles`, and
  some network-oriented plugins can return sparse or empty results. Prefer
  scan-based memory plugins when richer enumeration fails on this image.
- In memory-analysis workflows, if `python volatility3/vol.py -f
  data/base-dc-memory.img windows.psscan` works but `windows.pslist` fails,
  rerun with `-vvv` and preserve the debug stderr. `windows.netscan` is also
  often still worth running because it scans memory structures directly.
- The repo now includes DFIR-specific Obsidian skills for scaffolding,
  ingesting, and querying investigation-centric case folders under
  `./investigations/`.
- Investigation wikis plus the Spreadsheet of Doom are the default system of
  record for iterative analysis.
- The main goal of the Obsidian workflow is iterative analysis: keep raw
  outputs in `./investigations/`, but accumulate analyst judgement, task
  refinement, and artifact interpretation in the investigation wiki while the
  Spreadsheet of Doom holds the structured case record.
- The investigation scaffold now creates a single case root with sibling
  `wiki/`, `spreadsheet-of-doom/`, and `evidence/` folders, while the ingest
  skill builds file-level artifact notes under `wiki/artifacts/` and refreshes
  the hot cache without re-indexing the wiki itself.
- When generating markdown from shell here-doc templates, escape literal
  backticks. Unescaped markdown code spans can trigger shell command
  substitution and break the sync workflow.
- Command-first skills such as `windows-analysis` and `memory-analysis` do not
  need empty `scripts/` directories. Only keep `scripts/` when a skill ships
  real helper files.
- The repo now has an explicit iterative-investigation prompt: start from the
  wiki, decide whether the next step is more writing or more collection, then
  sync the new results back into the wiki so the loop can continue.
- The investigation wiki is not just an output destination. It is allowed to
  surface open questions that trigger additional Velociraptor or Volatility
  collection before the next wiki update.
- The default DFIR workflow goal is now a full initial evidence review that
  highlights all potentially malicious artifacts and leaves a structured queue
  for later workflow-specific review.
- The investigation scaffold should carry the same iterative analysis
  loop as the repo guide so each case folder can both absorb analysis updates
  and drive follow-up collection from open questions.
- When Velociraptor is rebuilt, kill every stale `velociraptor` process before
  testing the API client. Old GUI processes can survive a folder rebuild and
  cause TLS/API certificate mismatches against the fresh workspace.
- For a fresh Volatility 3 checkout, the first memory-analysis pass may need
  online symbol downloads before `windows.info` and `windows.psscan` can run.
  After the cache is populated, the repo-local `volatility3-cache/` can be
  reused for repeatable follow-up runs.
- The default first-pass Windows triage set should include
  `DetectRaptor.Windows.Detection.MFT`, not just later `Windows.NTFS.MFT`
  follow-up, so suspicious-file coverage starts in the initial collection wave.
- The evidence-of-execution workflow now includes `Windows.System.AppCompatPCA`
  as a launch-evidence artifact. Keep its interpretation caveat attached: it is
  useful where the PCA dictionary exists, but it is not universal execution
  coverage.
- `Windows.Registry.Hunter` should be treated as a large, follow-up registry
  sweep rather than a default first-pass collection. For dead-disk work, use
  `RemappingStrategy='None'` and narrowed category filters so the run is useful
  without being unnecessarily expensive.
- On this `base-dc` image, `Windows.System.TaskScheduler` surfaced a real
  `vssadmin Create Shadow` task authored by `shieldbase\\rsydow-a`, while
  `Windows.Sys.StartupItems` looked routine and
  `Windows.Registry.TaskCache.HiddenTasks` returned `0` rows.
- Shared cross-host indicators should live in the investigation Spreadsheet of
  Doom plus the case `wiki/`, instead of a separate top-level wiki tree.
- `Windows.Detection.BinaryHunter` is a good exact-path follow-up for
  suspicious binaries on dead-disk clients. On the current `subject_srv.exe`
  sample it produced stable cross-host hashes, signer details, PE version
  data, and the PDB path `E:\fresponse\x86_MT\F-Response Subjects\subject_srv.pdb`.
- When writing wiki findings or suspicious-artifact entries, keep the full
  command line instead of shortening with `...`; the exact arguments often
  carry the forensic context that later analysis depends on.
- `Windows.Registry.Hunter` with `RemappingStrategy='None'` is effective for
  dead-disk casework when split into system and investigation waves, and it
  can confirm service registrations, firewall rules, share mappings, and user
  context that other first-pass artifacts may miss.
- On the current `base-dc` and `base-file` images, Registry Hunter elevated
  `subject_srv.exe` from an execution lead to a confirmed cross-host automatic
  service (`F-Response Subject`) with a shared controller endpoint
  `base-hunt.shieldbase.lan:5682`.
- The Windows analysis workflow should treat `Windows.Detection.BinaryHunter`
  as the default exact-path follow-up for suspicious binaries so the case
  record captures hashes, signer details, PE metadata, imports, and PDB/build
  clues before later TI enrichment.
- On the current case, `subject_srv.exe` was clarified as a legitimate
  F-Response DFIR component. Treat signed remote-response tooling as a
  potential false positive for malware classification unless the question is
  authorization or misuse of legitimate tooling.
- The repo now includes a VirusTotal skill that mirrors the referenced
  `mcp-virustotal` report and relationship tool surface through a repo-local
  Python CLI, using `VIRUSTOTAL_API_KEY` first and then
  `./virustotal-config.json` as the credential fallback.
- VirusTotal enrichment in this repo should skip obviously internal domains and
  treat RFC1918 private IPs as low-value by default. In the case IOC tracker,
  use explicit `TI Status` values such as enriched, skipped as internal, or
  unsupported VT object type instead of leaving indicators as `Not checked`.
- The case scaffold is now investigation-centric and spreadsheet-first. Use
  one investigation root per investigation id, one Spreadsheet of Doom under
  `./investigations/<investigation_id>/spreadsheet-of-doom/`, and track
  individual hosts in `systems.csv` rather than creating one separate case
  folder per host.
- For case structure, use CSV as the durable source of truth and treat XLSX as
  an optional convenience export only.
- In the case layout, keep `wiki/`, `spreadsheet-of-doom/`, and `evidence/`
  as siblings under the investigation root, and regenerate
  `<investigation_id>_SoD.xlsx` after each sync so analysts can open the
  workbook directly.
- The sync workflow should index only `evidence/` and
  `spreadsheet-of-doom/`, not the entire investigation root, otherwise it will
  recursively ingest its own wiki pages as evidence.

### 2026-04-23

- The primary case record is now investigation-centric and spreadsheet-first:
  update Spreadsheet of Doom CSVs before updating wiki narrative pages.
- Keep `wiki/`, `spreadsheet-of-doom/`, and `evidence/` as siblings under the
  investigation root so the structured case record is easier to reach than the
  raw artifact tree.
- Each sync should regenerate `<investigation_id>_SoD.xlsx` in the
  investigation root for analyst-friendly review, while CSV remains
  the canonical format.
- The investigation record is investigation-centric. The canonical structured
  case record lives in Spreadsheet of Doom CSVs under
  `./investigations/<investigation_id>/spreadsheet-of-doom/`, while raw
  per-system outputs live under `evidence/systems/<system>/`.
- For durable case structure, prefer CSV as the source of truth and treat XLSX
  as an optional convenience export rather than the canonical repository
  format.
- The separate `./investigation-wikis/` tree has been retired. Keep the wiki
  directly under `./investigations/<investigation_id>/wiki/`.
- After case consolidation, remove legacy per-host investigation folders such
  as old `base-dc`, `base-file`, or `shared` trees so the active case root is
  the only durable investigation record under `./investigations/`.
- The Spreadsheet of Doom workbook export naming convention is now
  `<investigation_id>_SoD.xlsx`.
- Prefer the shorter `investigation`, `investigation-ingest`, and
  `investigation-query` skill names, and keep command examples
  investigation-centric by using reusable variables like
  `INVESTIGATION_ID`, `SYSTEM_NAME`, and `CLIENT_ID`.
- On the current `shieldbase-intrusion` case, the execution-analysis sweep
  reused finished flows where available and only queued missing artifacts for
  `base-file`; `base-dc` produced useful Amcache, UserAssist, and
  AppCompatCache rows, while BAM, Timeline, AppCompatPCA, and Prefetch were
  sparse or empty on both mapped dead-disk clients.
- In the current case, the highest-value IOC enrichment pattern was exact-path
  `Windows.Detection.BinaryHunter` followed by VirusTotal file lookup. That
  clarified `msadvapi2_32.exe` and `msadvapi2_64.exe` as unsigned binaries
  with `wormhole-windows` PDB paths, while downgrading
  `officedeploymenttool_9326.3600.exe` and `Mnemosyne.sys` to likely benign
  context.
- The Spreadsheet of Doom XLSX exporter now sets both header and body cells to
  14pt font by default. Rebuild the workbook through the investigation sync
  after changing spreadsheet content so the export stays consistent.
- Skill command examples should be repo-relative from the workspace root, such
  as `./venv/bin/python ./skills/...` and `cd ./velociraptor`, rather than
  embedding machine-specific absolute paths.
- The VirusTotal helper now defaults `get_file_report` to a compact
  analyst-friendly summary with a GUI `file_link`, `summary`,
  `details_summary`, and `telemetry_summary`, and the same compact-summary
  pattern now applies to URL, IP, and domain reports. Keep Slack formatting
  guidance in the skill documentation instead of emitting a stored
  `slack_summary` field. Report commands should not fetch relationships at
  all; use the dedicated `get_*_relationship` commands for threat actors or
  other pivots. Support `-raw` as a short alias for `--raw` on all report
  commands.
- Compact VT IP and domain summaries should include a trimmed
  `certificate_summary` when `last_https_certificate` is present, rather than
  storing the full certificate object or bulky WHOIS text.
- The preferred VirusTotal config shape is now a nested `virustotal` object in
  `./config.json`, though the helper still accepts the older flat key layout
  for backward compatibility.
- The VirusTotal skill documentation is now output-first. Keep report examples
  centered on compact JSON output and end the skill with Slack-posting
  guidance that tells the analyst to summarize the VT result with emoji
  headings instead of pasting full JSON into chat tools.
- On the current mapped dead-disk persistence sweep, `Windows.System.Services`,
  `Windows.Persistence.PermanentWMIEvents`, and
  `Windows.Sysinternals.Autoruns` all exported empty headerless CSVs across the
  case hosts. The useful persistence signal came instead from
  `Windows.Registry.Hunter.services`, `Windows.Registry.Hunter.persistence`,
  `Windows.Registry.Hunter.autoruns`, and `Windows.System.TaskScheduler`.
- Persistence-looking tasks can still be benign admin context. In this case,
  `Update_Sysmon_Rules` looked suspicious until export-first review tied it to
  a public `ion-storm/sysmon-config` `Auto_Update.bat` download on
  `base-wkstn-05`. Do not overcall these without adjacent evidence.

### 2026-04-30

- In this Codex environment, the reliable way to keep the local Velociraptor
  stack live was to run the GUI plus each mapped client supervisor in separate
  live terminal sessions; API `clients()` checks then showed fresh `LastSeen`
  updates for both `base-dc` and `base-file`.
- Status files under `velociraptor/mapped-clients/*/client-status.env` can
  look fresh even after the GUI has died; trust live listener checks plus a
  fresh `clients()` `LastSeen` query before assuming the stack is healthy.

### 2026-05-01

- For a straight Velociraptor GUI bring-up check, confirming listeners on
  `127.0.0.1:{8000,8001,8889}` plus a trivial API query against `scope()`
  was enough to verify the local workspace came up cleanly.
- The repo now has a `velociraptor-server-watchdog` skill. Its health model is
  listener checks plus a trivial API query, and the supervisor now refreshes
  both `server-status.env` and `server-session.env` after restarts so runtime
  metadata stays current.
- To restore the common dead-disk pair quickly, start the server watchdog
  first, then start the `base-dc` and `base-file` mapped-client supervisors
  and confirm both hostnames show fresh `LastSeen` values through `clients()`.

### 2026-05-03

- Rebuilding Velociraptor through `prep_dfir_tools.sh -t velociraptor` picked
  up the current GitHub release family (`v0.76`, local binary `0.76.5`).
- `add_mapped_client.sh` must resolve the evidence path to an absolute path
  before it `cd`s into `./velociraptor`; otherwise `deaddisk` can emit the
  placeholder remap `remappings: true` for valid relative `./data/*.E01`
  inputs.
- On a fresh Velociraptor workspace, the API can take longer than 20 seconds
  to become ready for `Server.Import.Extras`, `Server.Import.ArtifactExchange`,
  and `Server.Import.DetectRaptor`; the prep flow now waits longer before
  skipping those imports.

### 2026-05-04

- When the local Velociraptor stack is down, the reliable restore flow here is
  still: start `supervise_server.sh` in a live session, confirm listeners on
  `127.0.0.1:{8000,8001,8889}` plus `SELECT 1 AS ok FROM scope()`, then start
  `supervise_mapped_client.sh` for `base-dc` and `base-file` in separate live
  sessions and verify advancing `clients()` `LastSeen` values.

### 2026-05-12

- The repo now includes a `fetch-live-api-client` skill for remote live
  environments: it SSHes to the Velociraptor server, runs `config api_client`
  as the service user, and copies the resulting `api_client.yaml` into
  `~/.config/<server>/` for later live-analysis workflows.
- For live Linux triage through a remote API config, `Generic.Client.VQL`
  plus `Linux.Search.FileFinder` worked well for small, targeted challenge
  tasks. On the current `setup` host, `.viminfo` was more informative than
  `.bash_history` and revealed prior work on `level1.c`, `level2.c`, and a
  `readdir` preload hook in `healthcheck`.
- On the same `setup` host, Level 3 was hidden by a separate mount namespace,
  not by `LD_PRELOAD`: PID `2938` (`sleep infinity`) lived in mount namespace
  `mnt:[4026532330]` while PID 1 used `mnt:[4026531841]`, and
  `nsenter -t 2938 -m` exposed `/opt/secret/flag.txt` with content
  `Level 3 solved :)`.

### 2026-05-06

- `supervise_server.sh` should be launched with absolute workspace and
  `api_client.yaml` paths in a live session here; repo-relative arguments can
  break its `gui.log` and `gui.pid` writes after the script `cd`s into
  `./velociraptor`.
- The repo now has a separate `windows-collection` skill for queueing and
  status-checking bulk Windows collection flows without downloading rows, so a
  later analysis workflow can own storage-optimized VQL retrieval.
- `windows-collection` now supports target-type `ensure` checks that can reuse
  broader matching flows, and it treats a requested collection type as
  expected complete when the covering flow has finished even if some artifacts
  produced zero rows.
- `windows-collection` should match prior client flows by expected artifact
  specs so hunt-driven collections can be reused, while `--force-run` remains
  available when a fresh collection is explicitly required.
- The default bulk Windows collection set now omits
  `Windows.Registry.UserAssist` and `Windows.Registry.AppCompatCache`; use
  `Windows.Registry.Hunter` when those registry-backed views are needed.
- `windows-collection` now uses `pyvelociraptor` as a thin gRPC client with
  bundled VQL files under the skill, and it queues one flow per artifact so
  later export work can save one CSV per relevant result component.
- `windows-collection` polling is now a first-class step through a dedicated
  `poll` subcommand rather than ad hoc repeated `status` calls.
- `windows-collection` now treats polling as the default queue/ensure path;
  use `--no-poll` only when you explicitly want to return before the saved
  collection set reaches an expected-complete state.
- `windows-collection` now supports sectioned `Windows.Registry.Hunter`
  collection items, and the repo-default sections currently are `all`,
  `system-info`, and `execution` with `RemappingStrategy='None'`.
- For parameterized single-artifact client collections, `collect_client()`
  must be called with `artifacts=parse_json_array(data=Artifacts)` plus
  `spec=parse_json(data=Spec)`; passing only `artifacts=...` queues the
  artifact with default parameters and leaves `request.specs` empty.
- Collection-time registry section requests now collapse to one
  `Windows.Registry.Hunter[all]` flow with `RemappingStrategy='None'`; later
  analysis/export should filter categories out of that broad result set
  instead of recollecting `system-info` or `execution` separately.
- Notebook-style `Windows.Registry.Hunter` VQL that reads `source(source="Results")`
  should be rewritten for automation as
  `source(client_id=..., flow_id=..., artifact='Windows.Registry.Hunter/Results')`.
- For `Windows.Registry.Hunter`, the effective collection timeout must be
  passed as the top-level `collect_client(..., timeout=1800)` argument and
  matched against `request.timeout`; setting `timeout` only inside
  `request.specs` is not enough for reuse or for avoiding the default
  600-second behavior.
- Under each host's `velociraptor/` tree, keep collection metadata in
  `host-collection/`, analyst-ready derived outputs in `exports/`, and
  follow-up pivots such as BinaryHunter in `enrichments/`; older
  `execution-analysis/`, `registry-hunter/`, and `binaryhunter/` top-level
  folders were folded into that layout.
- `windows-analysis` should no longer own a separate bulk host-collection
  implementation; machine-wide collection belongs to `windows-collection`, and
  the old helper now only serves as a compatibility wrapper.
- The separate `windows-execution-analysis` and `windows-registry-analysis`
  skills were retired; machine-wide collection belongs to
  `windows-collection`, and any later result retrieval should be handled by
  collection-aware export workflows rather than standalone collectors.

### 2026-05-07

- `windows-collection` now exposes only two named collection types:
  `all` for the full baseline host set and `execution` for the execution-only
  subset; older `full` and group-oriented entrypoints should not be used in
  new workflows.
- `windows-collection` now supports repeatable `--env KEY=VALUE` arguments for
  a single explicit `--artifact`, so parameterized one-off collections can be
  queued without adding another special-case helper.
- The legacy `windows-analysis` collection wrapper now defaults to
  `--collection-type all` and forwards `--env` values, but the canonical
  interface remains `./skills/windows-collection/scripts/run_windows_collection.py`.
- `windows-collection` now owns the generic CSV download path too: `export`
  writes one `<ArtifactName>_full.csv` per finished non-registry artifact
  under each host's `velociraptor/exports/`, while `Windows.Registry.Hunter`
  is split into one CSV per `Category` from the `Results` component.
- Curated `Windows.Registry.Hunter` exports now live in repo `.vql` files
  under `skills/windows-collection/references/`; the first shipped profile is
  `execution`, which writes dedicated AppCompatCache, UserAssist, RADAR, and
  BAM CSVs from `Windows.Registry.Hunter/Results`.
- `windows-collection export-registry-hunter` now also has a `system-info`
  profile that writes a single `Windows.Registry.Hunter.SystemInfo.csv`
  export from the `System Info` category.
- `windows-collection export-registry-hunter` now also has a `web-browsers`
  profile that writes `Windows.Registry.Hunter.WebBrowsers.csv` from the
  `Web Browsers` category.
- `windows-collection export-registry-hunter` now also has a
  `volume-shadow-copies` profile that writes
  `Windows.Registry.Hunter.VolumeShadowCopies.csv` from the
  `Volume Shadow Copies` category.
- `windows-collection export-registry-hunter` now also has a `user-activity`
  profile that writes `Windows.Registry.Hunter.UserActivity.csv` from the
  `User Activity` category.
- `windows-collection export-registry-hunter` now also has a `user-accounts`
  profile that writes `Windows.Registry.Hunter.UserAccounts.csv` from the
  `User Accounts` category.
- `windows-collection export-registry-hunter` now also has a
  `threat-hunting` profile that writes
  `Windows.Registry.Hunter.ThreatHunting.csv` from the `Threat Hunting`
  category.
- `windows-collection export-registry-hunter` now also has a
  `third-party-applications` profile that writes
  `Windows.Registry.Hunter.ThirdPartyApplications.csv` from the
  `Third Party Applications` category.
- `windows-collection export-registry-hunter` now also has a `services`
  profile that writes `Windows.Registry.Hunter.Services.csv` from the
  `Services` category.
- `windows-collection export-registry-hunter` now also has a
  `network-shares` profile that writes
  `Windows.Registry.Hunter.NetworkShares.csv` from the `Network Shares`
  category.
- `windows-collection export-registry-hunter` now also has a `persistence`
  profile that writes `Windows.Registry.Hunter.Persistence.csv` from the
  `Persistence` category.
- `windows-collection export-registry-hunter` now also has a
  `program-execution` profile that writes
  `Windows.Registry.Hunter.ProgramExecution.csv` from the
  `Program Execution` category.
- `windows-collection export-registry-hunter` now also has a
  `microsoft-office` profile that writes
  `Windows.Registry.Hunter.MicrosoftOffice.csv` from the
  `Microsoft Office` category.
- `windows-collection export-registry-hunter` now also has a
  `microsoft-exchange` profile that writes
  `Windows.Registry.Hunter.MicrosoftExchange.csv` from the
  `Microsoft Exchange` category.
- `windows-collection export-registry-hunter` now also has an
  `installed-software` profile that writes
  `Windows.Registry.Hunter.InstalledSoftware.csv` from the
  `Installed Software` category.
- `windows-collection export-registry-hunter` now also has an `event-logs`
  profile that writes `Windows.Registry.Hunter.EventLogs.csv` from the
  `Event Logs` category.
- `windows-collection export-registry-hunter` now also has a `devices`
  profile that writes `Windows.Registry.Hunter.Devices.csv` from the
  `Devices` category.
- `windows-collection export-registry-hunter` now also has a `cloud-storage`
  profile that writes `Windows.Registry.Hunter.CloudStorage.csv` from the
  `Cloud Storage` category.
- `windows-collection export-registry-hunter` now also has an `autoruns`
  profile that writes `Windows.Registry.Hunter.Autoruns.csv` from the
  `Autoruns` category.
- The `windows-collection` execution set now includes
  `Windows.Registry.Hunter[all]`, so the default evidence-of-execution
  collection can reuse one broad registry-backed source for curated execution
  exports.
- `windows-collection export` now treats `Windows.Forensics.SRUM` as a
  multi-scope artifact and always writes separate CSVs for `Execution Stats`,
  `Application Resource Usage`, `Network Connections`, and `Network Usage`
  even when those scopes are empty.
- The `windows-collection` execution set now also includes
  `Windows.Forensics.SRUM`, so the default evidence-of-execution collection
  carries SRUM alongside Amcache, BAM, Timeline, Prefetch, AppCompatPCA, and
  `Windows.Registry.Hunter[all]`.
- `windows-collection` now auto-exports CSVs after `queue`, `ensure`, and
  `poll` once the requested set is complete; use `--no-export` only when you
  explicitly want to defer or suppress export generation.

### 2026-05-07

- `windows-collection` host state writes needed atomic file replacement and a
  tolerant first-document JSON reader because concurrent targeted collections
  could corrupt `host-collection-state.json`.
- The current case confirmed a design gap: one host-level state file and one
  generic export filename per artifact are not enough for iterative pivots.
  Targeted `FileFinder` and `BinaryHunter` runs can overwrite earlier saved
  request context or CSVs unless they are copied to unique names.
- The `windows-collection` execution set now includes
  `Windows.Forensics.RecentFileCache`, and the current `base-dc` and
  `base-file` images both returned clean `0`-row results for that artifact.
- In the current `shieldbase-intrusion` review, `base-file` carried the
  strongest malicious evidence: PowerShell download-and-execute activity,
  `n.ps1` staging into `C:\Windows\Temp\perfmon`, suspicious `PerfSvc.exe`,
  staged `install_wormhole` installers, and automatic Microsoft Advanced API
  services.
- In the same case, targeted `FileFinder` checks on `base-dc` did not confirm
  `C:\Users\spsql\n.ps1` or `C:\Windows\Temp\perfmon\**\*`, so the DC should
  currently be treated as a downstream or partially confirmed host rather than
  the primary staging origin.

### 2026-05-08

- The default investigation posture is now review-first: prefer existing
  exported artifact rows over new collection, and only recollect when the user
  explicitly requests it or the current exports cannot answer a concrete
  evidence question.
- Keep `windows-collection` as the dead-disk or offline mapped-client
  collection skill. Use the separate `windows-collection-live` skill for live
  remote Velociraptor collection, while sharing the same underlying
  collection/export engine.

### 2026-05-11

- The repo's documented investigation strategy is investigation-centric,
  spreadsheet-first, review-first, and iterative: keep raw evidence under
  `./investigations/<investigation_id>/evidence/`, structured case facts in
  `spreadsheet-of-doom/`, narrative judgement in `wiki/`, and let open
  questions in the case record drive targeted follow-up collection.
- The repo now has a bounded post-analysis timeline pivot for suspicious
  windows: reuse `windows-collection` with `--collection-type timeline` so
  `Windows.NTFS.MFT` and `Windows.EventLogs.EvtxHunter` share the same
  timebounds, and keep env-bound exports/manifests uniquely suffixed so repeat
  timeline hunts do not overwrite earlier pivots.
- The `windows-collection-live` wrapper should always be given the intended
  remote `--api-client`; otherwise it is easy to fall back to the repo-local
  Velociraptor workspace and miss the live case host entirely.
- A broad bounded `timeline` run with default `.` filters is useful as a raw
  review surface, but it gets noisy quickly: in the current
  `shieldbase-intrusion` case, the shared 2018-08-31T21:45:00Z to
  2018-09-06T23:00:00Z window produced 20,669 EVTX rows on `base-file` and
  278,099 EVTX rows on `base-dc`, so treat those exports as filter-once,
  reuse-many source files rather than a collection to repeat casually.
- To fully restore the local Velociraptor stack here, restart all three live
  shell supervisors together: `supervise_server.sh`,
  `supervise_mapped_client.sh base-dc`, and `supervise_mapped_client.sh
  base-file`. The `server-status.env` and `client-status.env` files can stay
  stale after a crash, so verify recovery with listeners plus a fresh
  `clients()` API query before assuming the GUI banner is truthful.
- `Windows.NTFS.MFT` exports in `windows-collection` are now intentionally
  projected to a stable timestamp/path schema instead of `SELECT *`, so later
  timeline review gets consistent CSV columns across generic and bounded MFT
  runs.
- `Windows.EventLogs.EvtxHunter` exports in `windows-collection` are also now
  intentionally projected to a stable analyst review schema with only
  `EventTime`, `Provider`, `EventID`, `EventRecordID`, `UserSID`, `Username`,
  `EventData`, and `UserData`, which keeps broad timeline EVTX exports smaller
  and easier to filter downstream.
- `Windows.EventLogs.RDPAuth` and `Windows.EventLogs.ExplicitLogon` are more
  useful when exported through fixed analyst-facing schemas instead of raw
  `SELECT *` dumps. Keep only the RDP/session, credential-use, target, and
  message fields needed for lateral-movement review.
- The offline `windows-collection` baseline now includes a dedicated
  `lateral-movement` section with `Windows.Detection.PublicIP`,
  `Windows.EventLogs.RDPAuth`, `Windows.EventLogs.ExplicitLogon`,
  `Windows.Registry.MountPoints2`, and
  `Windows.EventLogs.ServiceCreationComspec`, and it can also be targeted
  directly with `--collection-type lateral-movement`.

### 2026-05-12

- Newly added mapped dead-disk clients in this environment should be relaunched
  under live `supervise_mapped_client.sh` TTY sessions; one-shot background
  launches can register once and then die while stale `client-status.env`
  still says `online`.
- `./venv/bin/python ./skills/windows-collection/scripts/run_windows_collection.py export --artifact <artifact>`
  is the practical way to analyze partial results while a host's broader `all`
  collection target is still incomplete.
- On `base-rd-02`, the combination of `PSReadLine`, `Amcache`, `SRUM`, and
  exact-path `BinaryHunter` was enough to confirm the `msadvapi2_*` /
  `wormhole-windows` cluster without waiting for a fresh full Registry Hunter
  completion.
- On `dmz-ftp`, a narrow IOC-driven follow-up (`Windows.Search.FileFinder` plus
  exact-path `Windows.Detection.BinaryHunter`) quickly turned EVTX hints about
  `C:\\Windows\\Temp\\perfmon\\PWDumpX.exe` into durable on-disk evidence and
  should be preferred over another broad recollection pass.
- `windows-collection` should keep request-scoped state under
  `velociraptor/host-collection/requests/<request_id>/state.json` and treat
  `host-collection-state.json` as the latest-state compatibility pointer
  rather than the only durable saved collection record.
- The Spreadsheet of Doom now benefits from a dedicated `asset-map.csv` sheet
  for host-to-IP mappings and unresolved recurring source IPs; use that before
  deciding that more auth or lateral-movement collection is necessary.
- Cross-host IOC scoping should default to `./skills/windows-analysis/scripts/search_exports.py`
  over existing exports before queuing fresh collection.
- On these workstation memory images, Volatility `windows.cmdline`,
  `windows.cmdscan`, and `windows.consoles` can all remain empty even when a
  filtered `windows.strings.Strings` pass still preserves useful SharePoint,
  PSCP, or credential-shaped residue. Treat those as free-memory/session
  clues, not as reconstructed operator CLI history unless a PID-backed
  mapping or adjacent execution artefact corroborates them.
- Spreadsheet of Doom workbook exports now default both header and body cells
  to 18pt font for easier analyst review.
- When VT access is available, save the compact JSON reports under the case
  tree (for example `evidence/reference/virustotal/`) so TI-backed task
  tracker updates and later reporting can reuse the same outputs without
  rerunning lookups.
- When the customer confirms a legitimate response tool such as F-Response,
  update the case record promptly so the related service or binary is marked
  as confirmed benign case-context tooling rather than left as an open
  authorization review item.
- If multiple task-tracker items have already been answered by reviewed
  exports, update the tracker, asset map, indicators, timeline, and wiki in
  the same pass so the case record does not drift behind the evidence.
- Follow-up on `Windows.EventLogs.ExplicitLogon` should separate routine
  client-auth noise from higher-signal process-driven movement. Large
  `OUTLOOK.EXE` volumes to mail servers can be benign background auth, while
  smaller `WMIC.exe` and PowerShell subsets are usually the better lateral-
  movement review surface.
- Do not treat a repeated internal IP:port as malicious by default. In this
  case, `172.16.4.10:8080` appeared alongside suspicious PowerShell contexts
  on some hosts but also as the `proxy` field for a benign-looking Chrome
  updater BITS transfer on `base-rd-02`, so the surrounding process context
  matters more than the endpoint string alone.
- The dead-disk `windows-collection` persistence set now includes
  `Windows.System.Services`, `Windows.Registry.Hunter[all]`,
  `Windows.Persistence.PermanentWMIEvents`, and
  `Windows.Sysinternals.Autoruns`, but the WMI and Autoruns artifacts should
  still be treated as caveated on mapped drives because empty output there is
  expected.
- An exact-path `Windows.Search.FileFinder` pivot with `Upload_File=Y` and
  `Calculate_Hash=Y` is a good narrow follow-up for dead-disk persistence
  leads. On `base-rd-01`, it cleanly confirmed that `C:/Windows/Temp/1.bat`
  was not recoverable from the mapped image even though the scheduled task
  definition persisted in TaskScheduler and Registry Hunter.
- On the current Windows memory images, Volatility `windows.dumpfiles`,
  `filescan`, `handles`, and `cmdline` can all stay empty even when raw
  ASCII/UTF-16LE byte searches still preserve high-value IOC strings. For
  sparse snapshots, fall back to byte-level IOC searching before concluding
  that memory lacks useful file or command evidence.
- When a cleanup command survives only in memory, bracket its timing from
  adjacent disk and registry artefacts before claiming an execution time. In
  the current case, a memory-preserved `sd.exe ... n.ps1` command was best
  bounded by a deleted `sd.exe` MFT row (`2018-09-06T16:12:16Z` to
  `2018-09-06T16:14:05Z`) plus `SDelete\\EulaAccepted` at
  `2018-09-06T16:17:26Z`, rather than a nonexistent direct 4688 row.
