---
name: windows-collection-live
description: Queue Windows-focused Velociraptor collection flows against a live remote Velociraptor environment, track them to completion, and automatically export finished results to CSV. Use when you already have a remote API client config and want the same collection/export workflow without local dead-disk assumptions.
---

# Windows Collection Live

Use this skill for live remote Velociraptor collection when you already have a
valid API client config for the target environment. This skill reuses the same
shared collection engine as `windows-collection`, but it is intended for
live/remote analysis rather than repo-local dead-disk mapped-client work.

This skill does not do analyst interpretation. Once exports exist, analysis
should prefer reviewing those exported rows over starting new collection
unless recollection is explicitly requested or the exports cannot answer the
evidence question.

## Workflow

1. Confirm you have a valid remote Velociraptor `api_client.yaml`.
2. Confirm the target client is online and has a recent `LastSeen`.
3. Resolve the target collection type or explicit artifact into individual artifacts.
4. Check whether each artifact already has a matching prior flow with the expected arguments.
5. Reuse matching finished or in-flight flows artifact-by-artifact.
6. Queue a new Velociraptor flow per missing artifact, or queue fresh flows for all requested artifacts when you explicitly force a rerun.
7. Save the per-artifact flow map under the investigation evidence tree.
8. Poll the saved per-artifact flow state until the requested set is finished.
9. Automatically export finished flows to CSV under the host `velociraptor/exports/` tree unless you explicitly disable export.
10. Treat those exports as the default handoff for later analyst review and avoid recollecting the same evidence unless you explicitly need a rerun or a missing artifact scope.

## Live Collection Helper

Run from the repo root. Pass the remote API config explicitly.

Ensure the live execution-focused subset exists:

```bash
./venv/bin/python ./skills/windows-collection-live/scripts/run_windows_collection_live.py \
  --api-client /path/to/remote-api_client.yaml \
  ensure \
  --investigation-id shieldbase-intrusion \
  --host live-host-01 \
  --collection-type execution
```

Queue the default full set on a live remote host:

```bash
./venv/bin/python ./skills/windows-collection-live/scripts/run_windows_collection_live.py \
  --api-client /path/to/remote-api_client.yaml \
  queue \
  --investigation-id shieldbase-intrusion \
  --host live-host-01 \
  --collection-type all
```

Use a non-root org when needed:

```bash
./venv/bin/python ./skills/windows-collection-live/scripts/run_windows_collection_live.py \
  --api-client /path/to/remote-api_client.yaml \
  --org-id root \
  check \
  --investigation-id shieldbase-intrusion \
  --host live-host-01 \
  --collection-type all
```

Queue one explicit live artifact with custom variables:

```bash
./venv/bin/python ./skills/windows-collection-live/scripts/run_windows_collection_live.py \
  --api-client /path/to/remote-api_client.yaml \
  ensure \
  --investigation-id shieldbase-intrusion \
  --host live-host-01 \
  --artifact Windows.Search.FileFinder \
  --env Glob='C:\\Windows\\Temp\\*.exe'
```

Export finished results later:

```bash
./venv/bin/python ./skills/windows-collection-live/scripts/run_windows_collection_live.py \
  --api-client /path/to/remote-api_client.yaml \
  export \
  --investigation-id shieldbase-intrusion \
  --host live-host-01 \
  --collection-type execution
```

Curated Registry Hunter export:

```bash
./venv/bin/python ./skills/windows-collection-live/scripts/run_windows_collection_live.py \
  --api-client /path/to/remote-api_client.yaml \
  export-registry-hunter \
  --investigation-id shieldbase-intrusion \
  --host live-host-01 \
  --profile execution
```

## Notes

- This skill is for live/remote Velociraptor use where Volatility 3 is not the
  default process-memory path.
- It currently reuses the same named collection types and export logic as
  `windows-collection`, but it is documented separately so live-only artifact
  expansion can diverge later without changing the dead-disk workflow.
- Keep the remote API client config outside the repo when it contains live
  environment access material.
- The wrapper forwards into
  `./skills/windows-collection/scripts/run_windows_collection.py` with
  explicit `--api-client` and `--org-id` values, so the collection/export
  behavior stays shared.
