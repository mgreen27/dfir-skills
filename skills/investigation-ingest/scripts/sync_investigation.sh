#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: sync_investigation.sh <investigation_id> [investigation_dir]

Refresh an investigation-centric case wiki from evidence and Spreadsheet of
Doom outputs.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  exit 0
fi

INVESTIGATION_ID="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
INVESTIGATION_DIR="${2:-${REPO_ROOT}/investigations/${INVESTIGATION_ID}}"
WIKI_DIR="${INVESTIGATION_DIR}/wiki"
SOD_DIR="${INVESTIGATION_DIR}/spreadsheet-of-doom"
EVIDENCE_DIR="${INVESTIGATION_DIR}/evidence"
SYSTEMS_DIR="${EVIDENCE_DIR}/systems"
XLSX_EXPORT="${INVESTIGATION_DIR}/${INVESTIGATION_ID}_SoD.xlsx"
TODAY="$(date -u +"%Y-%m-%d")"
NOW_ISO="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
INIT_SCRIPT="${REPO_ROOT}/skills/investigation/scripts/init_investigation.sh"
EXPORT_SCRIPT="${REPO_ROOT}/skills/investigation/scripts/export_spreadsheet_of_doom.py"
PYTHON_BIN="${REPO_ROOT}/venv/bin/python3"

if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="python3"
fi

if [[ ! -d "${INVESTIGATION_DIR}" ]]; then
  printf 'Investigation directory not found: %s\n' "${INVESTIGATION_DIR}" >&2
  exit 1
fi

"${INIT_SCRIPT}" "${INVESTIGATION_ID}" "${INVESTIGATION_DIR}"
"${PYTHON_BIN}" "${EXPORT_SCRIPT}" "${SOD_DIR}" "${XLSX_EXPORT}"
find "${WIKI_DIR}/artifacts" -type f ! -name '_index.md' -delete

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
  note_path="${WIKI_DIR}/artifacts/${note_slug}.md"
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
investigation: "${INVESTIGATION_ID}"
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
- Read the raw output through the case \`evidence/\` directory or this absolute path.
- Capture durable structured facts in the Spreadsheet of Doom when relevant.
- Use [[analysis]] for narrative interpretation and [[meta/sync-status]] to
  confirm the last case sync.
EOF

  printf -- "- [[artifacts/%s|%s]]\n" "${note_slug}" "${base_name}"
}

artifact_index_lines=""
evidence_lines=""

if [[ -d "${EVIDENCE_DIR}" ]]; then
while IFS= read -r source_path; do
  relative_path="${source_path#${INVESTIGATION_DIR}/}"
  family="${relative_path%%/*}"
  if [[ "${relative_path}" == "${family}" ]]; then
    family="root"
  fi
  artifact_index_lines+=$(render_artifact_note "${source_path}" "${relative_path}" "${family}")
  artifact_index_lines+=$'\n'
  evidence_lines+="- \`${relative_path}\`"$'\n'
done < <(find "${EVIDENCE_DIR}" -type f ! -name '.DS_Store' ! -name 'investigation-notes.md' ! -name 'investigation-results.md' | sort)
fi

if [[ -d "${SOD_DIR}" ]]; then
while IFS= read -r source_path; do
  relative_path="${source_path#${INVESTIGATION_DIR}/}"
  artifact_index_lines+=$(render_artifact_note "${source_path}" "${relative_path}" "spreadsheet-of-doom")
  artifact_index_lines+=$'\n'
done < <(find "${SOD_DIR}" -type f ! -name '.DS_Store' | sort)
fi

cat > "${WIKI_DIR}/artifacts/_index.md" <<EOF
---
type: meta
title: "${INVESTIGATION_ID} Artifact Index"
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

cat > "${WIKI_DIR}/evidence.md" <<EOF
---
type: question
title: "${INVESTIGATION_ID} Evidence"
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
- \`${EVIDENCE_DIR}\`

## Structured Case Record
- Spreadsheet of Doom root: \`${SOD_DIR}\`
- Per-system raw output root: \`${SYSTEMS_DIR}\`

## Current Files
${evidence_lines:-"- No raw output files were found.\n"}

## Notes
- Browse the raw files through the \`evidence/\` directory in this case folder.
- File-level wiki notes are indexed in [[artifacts/_index]].
EOF

cat > "${WIKI_DIR}/spreadsheet-of-doom.md" <<EOF
---
type: meta
title: "${INVESTIGATION_ID} Spreadsheet Of Doom"
created: ${TODAY}
updated: ${TODAY}
tags:
  - spreadsheet-of-doom
  - dfir
  - investigation
status: active
---

# Spreadsheet Of Doom

## Canonical Structured Sheets

- [timeline.csv](../spreadsheet-of-doom/timeline.csv)
- [systems.csv](../spreadsheet-of-doom/systems.csv)
- [users.csv](../spreadsheet-of-doom/users.csv)
- [host-indicators.csv](../spreadsheet-of-doom/host-indicators.csv)
- [network-indicators.csv](../spreadsheet-of-doom/network-indicators.csv)
- [task-tracker.csv](../spreadsheet-of-doom/task-tracker.csv)
- [evidence-tracker.csv](../spreadsheet-of-doom/evidence-tracker.csv)
- [keywords.csv](../spreadsheet-of-doom/keywords.csv)
- [Workbook Export](../${INVESTIGATION_ID}_SoD.xlsx)

## Current Usage

- Track each host in \`systems.csv\`.
- Track atomic host artifacts in \`host-indicators.csv\`.
- Track network and infrastructure leads in \`network-indicators.csv\`.
- Track unanswered questions and next actions in \`task-tracker.csv\`.
- Use \`analysis.md\` for short narrative synthesis when the spreadsheet alone
  is not enough.
- Refresh the workbook export first when the CSV sheets change.
EOF

cat > "${WIKI_DIR}/meta/sync-status.md" <<EOF
---
type: meta
title: "${INVESTIGATION_ID} Sync Status"
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
- Raw source root: \`${EVIDENCE_DIR}\`
- Spreadsheet of Doom root: \`${SOD_DIR}\`
- Case root: \`${INVESTIGATION_DIR}\`
- Workbook export: \`${XLSX_EXPORT}\`
- Artifact notes refreshed from the current evidence and Spreadsheet of Doom outputs.
EOF

cat > "${WIKI_DIR}/hot.md" <<EOF
---
type: meta
title: "${INVESTIGATION_ID} Hot Cache"
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
${NOW_ISO}. Investigation case sync completed.

## Key Recent Facts
- Investigation: \`${INVESTIGATION_ID}\`
- Raw evidence path: \`${EVIDENCE_DIR}\`
- Structured case record: [[spreadsheet-of-doom]]
- Workbook export refreshed: \`${XLSX_EXPORT}\`
- Artifact notes refreshed under [[artifacts/_index]]

## Recent Changes
- Refreshed: [[evidence]]
- Refreshed: [[spreadsheet-of-doom]]
- Refreshed: \`${INVESTIGATION_ID}_SoD.xlsx\`
- Refreshed: [[hot]]
- Refreshed: [[meta/sync-status]]

## Active Threads
- Continue iterative case review from the Spreadsheet of Doom and [[analysis]].
EOF

LOG_FILE="${WIKI_DIR}/log.md"
TMP_LOG="$(mktemp)"
{
  sed -n '1,1000p' "${LOG_FILE}"
  printf '\n- %s: Synced evidence from `%s` and refreshed Spreadsheet of Doom outputs under `%s`.\n' "${NOW_ISO}" "${EVIDENCE_DIR}" "${SOD_DIR}"
} > "${TMP_LOG}"
mv "${TMP_LOG}" "${LOG_FILE}"
