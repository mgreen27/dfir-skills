---
name: velociraptor-server-watchdog
description: Keep the local Velociraptor GUI workspace alive with a lightweight watchdog that restarts the server when listeners disappear or the API stops answering simple health queries.
---

# Velociraptor Server Watchdog

Run the server watchdog when you want the local Velociraptor GUI, API, and
frontend listeners to stay available during iterative DFIR work.

## Workflow

1. Confirm the repo-local Velociraptor workspace exists under `./velociraptor`.
2. Start the watchdog wrapper.
3. Let the watchdog reuse the current GUI process if it is already healthy.
4. If the server is down or unhealthy, let the watchdog restart it.
5. Check the status and session files under `./velociraptor/` for runtime
   state.

## Commands

Run from the repo root:

```bash
./skills/velociraptor-server-watchdog/scripts/start_server_watchdog.sh
```

If you want the supervisor loop directly in the foreground:

```bash
bash ./skills/velociraptor-server-watchdog/scripts/supervise_server.sh \
  ./velociraptor \
  ./velociraptor/api_client.yaml
```

## Outputs

The watchdog writes runtime state under:

```text
./velociraptor/
```

Relevant files:

- `gui.log`
- `gui.pid`
- `server-status.env`
- `server-session.env`
- `server-supervisor.log`
- `server-supervisor.pid`

## Notes

- This skill expects `prep-dfir-tools` to have already staged and initialized
  Velociraptor under `./velociraptor/`.
- Health checks require both live listeners and a successful API query through
  `api_client.yaml`.
- If the GUI is already healthy, the watchdog adopts the existing server
  process instead of forcing a restart.
- In this Codex environment, a dedicated live session is still the most
  reliable way to keep the watchdog alive for long-running work.
