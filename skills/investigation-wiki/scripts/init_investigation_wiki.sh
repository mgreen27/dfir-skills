#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: init_investigation_wiki.sh <hostname> [investigation_dir] [vault_dir]

Create or reuse a per-host Obsidian investigation vault.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  exit 0
fi

HOSTNAME="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
INVESTIGATION_DIR="${2:-${REPO_ROOT}/investigations/${HOSTNAME}}"
VAULT_DIR="${3:-${REPO_ROOT}/investigation-wikis/${HOSTNAME}}"
TODAY="$(date -u +"%Y-%m-%d")"
NOW_ISO="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

mkdir -p \
  "${VAULT_DIR}/wiki/artifacts" \
  "${VAULT_DIR}/wiki/questions" \
  "${VAULT_DIR}/wiki/meta"

ln -sfn "${INVESTIGATION_DIR}" "${VAULT_DIR}/evidence"

write_if_missing() {
  local target="$1"
  if [[ ! -e "${target}" ]]; then
    cat > "${target}"
  fi
}

write_if_missing "${VAULT_DIR}/AGENTS.md" <<EOF
# ${HOSTNAME} Investigation Vault

## Purpose

This vault is the durable analyst workspace for the \`${HOSTNAME}\` DFIR
investigation.

## Operating Rules

1. Treat \`wiki/\` as the system of record for iterative analysis.
2. Keep raw outputs under \`${INVESTIGATION_DIR}\` and browse them through the
   \`evidence\` symlink.
3. Update \`wiki/hot.md\`, \`wiki/findings.md\`, \`wiki/timeline.md\`,
   \`wiki/leads.md\`, and \`wiki/log.md\` after meaningful case changes.
4. Do not edit raw result files in the evidence directory.
5. Prefer exact paths, timestamps, hashes, flow ids, and plugin names.
EOF

write_if_missing "${VAULT_DIR}/wiki/index.md" <<EOF
---
type: meta
title: "${HOSTNAME} Investigation Index"
created: ${TODAY}
updated: ${TODAY}
tags:
  - meta
  - dfir
  - investigation
status: active
---

# ${HOSTNAME} Investigation Index

- [[overview]]
- [[findings]]
- [[timeline]]
- [[leads]]
- [[evidence]]
- [[hot]]
- [[log]]
- [[artifacts/_index]]
- [[questions/_index]]
- [[meta/sync-status]]
EOF

write_if_missing "${VAULT_DIR}/wiki/hot.md" <<EOF
---
type: meta
title: "${HOSTNAME} Hot Cache"
created: ${TODAY}
updated: ${TODAY}
tags:
  - meta
  - hot-cache
  - dfir
status: active
---

# Recent Context

## Last Updated
${NOW_ISO}. Vault scaffolded.

## Key Recent Facts
- Host: \`${HOSTNAME}\`
- Raw evidence path: \`${INVESTIGATION_DIR}\`

## Recent Changes
- Created: [[overview]]
- Created: [[findings]]
- Created: [[timeline]]
- Created: [[leads]]
- Created: [[evidence]]

## Active Threads
- Initial vault setup
EOF

write_if_missing "${VAULT_DIR}/wiki/log.md" <<EOF
---
type: meta
title: "${HOSTNAME} Investigation Log"
created: ${TODAY}
updated: ${TODAY}
tags:
  - meta
  - log
  - dfir
status: active
---

# Investigation Log

- ${NOW_ISO}: Scaffolded investigation wiki for \`${HOSTNAME}\`.
EOF

write_if_missing "${VAULT_DIR}/wiki/overview.md" <<EOF
---
type: meta
title: "${HOSTNAME} Overview"
created: ${TODAY}
updated: ${TODAY}
tags:
  - overview
  - dfir
  - investigation
status: active
---

# Overview

## Host
- Hostname: \`${HOSTNAME}\`
- Raw evidence: \`${INVESTIGATION_DIR}\`

## Scope
- Fill in the host role, evidence scope, and primary questions.

## Current Assessment
- Add the current analyst position here.
EOF

write_if_missing "${VAULT_DIR}/wiki/findings.md" <<EOF
---
type: question
title: "${HOSTNAME} Findings"
created: ${TODAY}
updated: ${TODAY}
tags:
  - findings
  - dfir
  - investigation
status: active
---

# Findings

## Executive Summary
- Add the current case summary here.

## Confirmed Findings
- 

## Leads
- 

## Gaps
- 

## Next Actions
- 
EOF

write_if_missing "${VAULT_DIR}/wiki/timeline.md" <<EOF
---
type: question
title: "${HOSTNAME} Timeline"
created: ${TODAY}
updated: ${TODAY}
tags:
  - timeline
  - dfir
  - investigation
status: active
---

# Timeline

| Timestamp | Event | Source |
|---|---|---|
| | | |
EOF

write_if_missing "${VAULT_DIR}/wiki/leads.md" <<EOF
---
type: question
title: "${HOSTNAME} Leads"
created: ${TODAY}
updated: ${TODAY}
tags:
  - leads
  - dfir
  - investigation
status: active
---

# Leads

## Active Leads
- 

## Cleared Leads
- 
EOF

write_if_missing "${VAULT_DIR}/wiki/evidence.md" <<EOF
---
type: question
title: "${HOSTNAME} Evidence"
created: ${TODAY}
updated: ${TODAY}
tags:
  - evidence
  - dfir
  - investigation
status: active
---

# Evidence

## Raw Output Root
- \`${INVESTIGATION_DIR}\`

## Notes
- Browse the raw case data through the \`evidence\` symlink.
- Use [[artifacts/_index]] for generated file-level notes.
EOF

write_if_missing "${VAULT_DIR}/wiki/artifacts/_index.md" <<EOF
---
type: meta
title: "${HOSTNAME} Artifact Index"
created: ${TODAY}
updated: ${TODAY}
tags:
  - meta
  - artifacts
  - dfir
status: active
---

# Artifact Index

- Run the ingest skill to populate artifact notes.
EOF

write_if_missing "${VAULT_DIR}/wiki/questions/_index.md" <<EOF
---
type: meta
title: "${HOSTNAME} Questions Index"
created: ${TODAY}
updated: ${TODAY}
tags:
  - meta
  - questions
  - dfir
status: active
---

# Questions Index

- Add durable analyst questions and answers here.
EOF

write_if_missing "${VAULT_DIR}/wiki/meta/sync-status.md" <<EOF
---
type: meta
title: "${HOSTNAME} Sync Status"
created: ${TODAY}
updated: ${TODAY}
tags:
  - meta
  - sync
  - dfir
status: active
---

# Sync Status

- No ingestion run has been recorded yet.
EOF
