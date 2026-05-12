---
name: fetch-live-api-client
description: Generate a live Velociraptor api_client.yaml on a remote server over SSH and copy it into the local ~/.config/<server>/ folder for later live analysis. Use when you have shell access to a Velociraptor server and need a local API client config for skills such as windows-collection-live.
---

# Fetch Live API Client

Use this skill when the API client config lives on a remote Velociraptor server
and you want a repeatable way to generate it remotely and copy it down to the
local machine for live collection work.

The helper script:

1. SSHes to the remote server.
2. Runs `velociraptor config api_client` as the configured service user.
3. Writes the generated file to the remote Velociraptor config directory.
4. Copies the file into `~/.config/<server>/` by default.

## Helper

Run from the repo root:

```bash
./skills/fetch-live-api-client/scripts/fetch_live_api_client.sh \
  --server si7 \
  --api-name skynet
```

This matches the common environment defaults:

- remote SSH user: `root`
- remote Velociraptor service user: `velociraptor`
- remote binary: `/usr/local/bin/velociraptor`
- remote server config: `/etc/velociraptor/server.config.yaml`
- remote generated file: `/etc/velociraptor/<api-name>_api_client.yaml`
- local destination root: `~/.config/<server>/`
- SSH identity: `~/.ssh/infoguard` if it exists

## Examples

Use a different SSH identity:

```bash
./skills/fetch-live-api-client/scripts/fetch_live_api_client.sh \
  --server si7 \
  --api-name skynet \
  --identity ~/.ssh/another_key
```

Write into a different local folder name:

```bash
./skills/fetch-live-api-client/scripts/fetch_live_api_client.sh \
  --server 10.10.3.9 \
  --local-folder si7 \
  --api-name skynet
```

Preview the exact SSH and SCP commands without executing them:

```bash
./skills/fetch-live-api-client/scripts/fetch_live_api_client.sh \
  --server si7 \
  --api-name skynet \
  --dry-run
```

## Notes

- Keep live remote API configs outside the repo.
- The copied file is intended to be reused by live-analysis workflows such as
  `windows-collection-live`.
- If the remote host requires a different SSH user, service account, config
  path, or Velociraptor binary path, pass those explicitly instead of editing
  the script ad hoc.
