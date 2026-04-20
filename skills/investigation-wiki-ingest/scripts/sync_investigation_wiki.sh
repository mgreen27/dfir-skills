#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: sync_investigation_wiki.sh <hostname> [investigation_dir] [vault_dir]

Refresh a per-host Obsidian investigation vault from raw case outputs.
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
INIT_SCRIPT="${REPO_ROOT}/skills/investigation-wiki/scripts/init_investigation_wiki.sh"

if [[ ! -d "${INVESTIGATION_DIR}" ]]; then
  printf 'Investigation directory not found: %s\n' "${INVESTIGATION_DIR}" >&2
  exit 1
fi

"${INIT_SCRIPT}" "${HOSTNAME}" "${INVESTIGATION_DIR}" "${VAULT_DIR}"

slugify() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g; s/-\{2,\}/-/g; s/^-//; s/-$//'
}

render_artifact_note() {
  local source_path="$1"
  local relative_path="$2"
  local family="$3"
  local base_name extension note_slug note_path size_bytes modified_at

  base_name="$(basename "${source_path}")"
  extension="${base_name##*.}"
  note_slug="$(slugify "${family}-${base_name}")"
  note_path="${VAULT_DIR}/wiki/artifacts/${note_slug}.md"
  size_bytes="$(wc -c < "${source_path}" | tr -d ' ')"
  modified_at="$(date -u -r "${source_path}" +"%Y-%m-%dT%H:%M:%SZ")"

  cat > "${note_path}" <<EOF
---
type: source
title: "${base_name}"
created: ${TODAY}
updated: ${TODAY}
tags:
  - source
  - artifact-output
  - dfir
status: active
source_type: file
artifact_family: "${family}"
host: "${HOSTNAME}"
---

# Artifact Output

## File Details
- Absolute path: \`${source_path}\`
- Relative path: \`${relative_path}\`
- Family: \`${family}\`
- Extension: \`${extension}\`
- Size bytes: \`${size_bytes}\`
- Modified: \`${modified_at}\`

## Review Guidance
- Read the raw output through the \`evidence\` symlink or this absolute path.
- Record analyst interpretation in [[findings]], [[leads]], or [[timeline]].
- Use [[meta/sync-status]] to confirm the last vault refresh.
EOF

  printf -- "- [[artifacts/%s|%s]]\n" "${note_slug}" "${base_name}"
}

artifact_index_lines=""
evidence_lines=""

while IFS= read -r source_path; do
  relative_path="${source_path#${INVESTIGATION_DIR}/}"
  family="${relative_path%%/*}"
  if [[ "${relative_path}" == "${family}" ]]; then
    family="root"
  fi
  artifact_index_lines+=$(render_artifact_note "${source_path}" "${relative_path}" "${family}")
  artifact_index_lines+=$'\n'
  evidence_lines+="- \`${relative_path}\`\n"
done < <(find "${INVESTIGATION_DIR}" -type f ! -name '.DS_Store' ! -name 'investigation-notes.md' ! -name 'investigation-results.md' | sort)

cat > "${VAULT_DIR}/wiki/artifacts/_index.md" <<EOF
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

${artifact_index_lines:-"- No artifact files were found.\n"}
EOF

cat > "${VAULT_DIR}/wiki/evidence.md" <<EOF
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

## Current Files
${evidence_lines:-"- No raw output files were found.\n"}

## Notes
- Browse the raw files through the \`evidence\` symlink in this vault.
- File-level wiki notes are indexed in [[artifacts/_index]].
EOF

cat > "${VAULT_DIR}/wiki/meta/sync-status.md" <<EOF
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

- Last sync: ${NOW_ISO}
- Raw source root: \`${INVESTIGATION_DIR}\`
- Vault root: \`${VAULT_DIR}\`
- Artifact notes refreshed from the current raw case outputs.
EOF

cat > "${VAULT_DIR}/wiki/hot.md" <<EOF
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
${NOW_ISO}. Investigation wiki sync completed.

## Key Recent Facts
- Host: \`${HOSTNAME}\`
- Raw evidence path: \`${INVESTIGATION_DIR}\`
- Artifact notes refreshed under [[artifacts/_index]]

## Recent Changes
- Refreshed: [[evidence]]
- Refreshed: [[hot]]
- Refreshed: [[meta/sync-status]]
- Refreshed: [[artifacts/_index]]

## Active Threads
- Continue iterative artifact review in [[findings]], [[leads]], and [[timeline]].
EOF

legacy_results="${INVESTIGATION_DIR}/investigation-results.md"
legacy_notes="${INVESTIGATION_DIR}/investigation-notes.md"

if [[ -f "${legacy_results}" ]]; then
  cat > "${VAULT_DIR}/wiki/meta/legacy-flat-results.md" <<EOF
---
type: meta
title: "${HOSTNAME} Legacy Flat Results"
created: ${TODAY}
updated: ${TODAY}
tags:
  - meta
  - legacy
  - dfir
status: migrated
---

# Legacy Flat Results

The content below was migrated from \`${legacy_results}\`.

EOF
  cat "${legacy_results}" >> "${VAULT_DIR}/wiki/meta/legacy-flat-results.md"

  if grep -q "Add the current case summary here." "${VAULT_DIR}/wiki/findings.md"; then
    cat > "${VAULT_DIR}/wiki/findings.md" <<EOF
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

Migrated from the legacy flat case summary. Continue updating this page as the
authoritative analyst narrative for the case.

EOF
    cat "${legacy_results}" >> "${VAULT_DIR}/wiki/findings.md"
  fi
fi

if [[ -f "${legacy_notes}" ]]; then
  cat > "${VAULT_DIR}/wiki/meta/legacy-flat-notes.md" <<EOF
---
type: meta
title: "${HOSTNAME} Legacy Flat Notes"
created: ${TODAY}
updated: ${TODAY}
tags:
  - meta
  - legacy
  - dfir
status: migrated
---

# Legacy Flat Notes

The content below was migrated from \`${legacy_notes}\`.

EOF
  cat "${legacy_notes}" >> "${VAULT_DIR}/wiki/meta/legacy-flat-notes.md"

  if ! grep -q "## Migrated Legacy Notes" "${VAULT_DIR}/wiki/leads.md"; then
    cat >> "${VAULT_DIR}/wiki/leads.md" <<EOF

## Migrated Legacy Notes

The older flat analyst notes were migrated into [[meta/legacy-flat-notes]].
Use that page as reference, then keep new lead triage on this page.
EOF
  fi
fi

LOG_FILE="${VAULT_DIR}/wiki/log.md"
TMP_LOG="$(mktemp)"
{
  sed -n '1,1000p' "${LOG_FILE}"
  printf '\n- %s: Synced raw outputs from `%s` into the vault.\n' "${NOW_ISO}" "${INVESTIGATION_DIR}"
} > "${TMP_LOG}"
mv "${TMP_LOG}" "${LOG_FILE}"
