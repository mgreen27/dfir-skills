---
name: add-velociraptor-mapped-client
description: Attach a dead-disk image or mounted Windows evidence directory to a local Velociraptor GUI workspace as a mapped client. Use when you need to check whether the local Velociraptor GUI is running, start it if needed, generate a remapping file, and launch the client side so the evidence appears in GUI mode.
---

# Add Velociraptor Mapped Client

Run `scripts/add_mapped_client.sh` to attach an offline Windows image or mounted
directory to the local Velociraptor workspace.

## Workflow

1. Confirm the repo-local Velociraptor workspace exists under `./velociraptor`.
2. Validate that the evidence path is a real image or mounted Windows directory.
3. Reuse the existing GUI instance if it is already listening.
4. Start local GUI mode if it is not already running.
5. Generate a remapping file for the evidence.
6. Launch a supervised background Velociraptor client with that remap.
7. Keep the client online by watching both the local PID and the Velociraptor
   `LastSeen` timestamp.

## Commands

Run from the repo root:

```bash
./skills/add-velociraptor-mapped-client/scripts/add_mapped_client.sh /path/to/image.E01
```

Set an explicit virtual host name for the mapped client:

```bash
./skills/add-velociraptor-mapped-client/scripts/add_mapped_client.sh \
  -n dead-disk-lab01 \
  /path/to/image.E01
```

Attach a mounted Windows directory instead of an image:

```bash
./skills/add-velociraptor-mapped-client/scripts/add_mapped_client.sh \
  /mnt/windows-volume
```

## Outputs

If `-n` is not provided, the script derives the hostname from the image or
folder name and uses that for the dead-disk client identity.

For each attached image, the script creates a workspace under:

```text
./velociraptor/mapped-clients/<name>/
```

That folder contains:

- `client.config.yaml`
- `remapping.yaml`
- `client-info.json`
- `client-info.log`
- `client.log`
- `client.pid`
- `client-status.env`
- `supervisor.log`
- `supervisor.pid`
- `session.env`

The GUI log lives at:

```text
./velociraptor/gui.log
```

## Notes

- This skill expects `prep-dfir-tools` to have already staged and initialized
  Velociraptor under `./velociraptor/`.
- The script checks the GUI listener and only starts `./velociraptor gui -v
  --datastore=. --nobrowser --noclient` when the local GUI is not already
  reachable.
- The script validates the generated remapping file so placeholder files such as
  `remappings: true` are rejected before the client starts.
- Each mapped client gets its own `client.config.yaml`, temp directory, and
  writeback file so the image name can map to a stable Velociraptor hostname
  instead of reusing a shared client identity.
- The client now runs under a local supervisor loop. If the mapped client
  process dies or the API `LastSeen` value goes stale, the supervisor restarts
  it automatically.
- The script looks up the enrolled client through `api_client.yaml` using a
  `clients()` VQL query that reads the client record populated by
  `Generic.Client.Info/BasicInformation`, then writes the result to
  `client-info.json`.
- Dead-disk clients are suitable for offline filesystem and registry artifacts,
  not true live-response plugins that depend on running processes or live
  network state.
