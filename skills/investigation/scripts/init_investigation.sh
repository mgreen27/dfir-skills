#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: init_investigation.sh <investigation_id> [investigation_dir]

Create or reuse an investigation-centric case folder with sibling `wiki/`,
`spreadsheet-of-doom/`, and `evidence/` directories.
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
TODAY="$(date -u +"%Y-%m-%d")"
NOW_ISO="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

mkdir -p \
  "${SYSTEMS_DIR}" \
  "${SOD_DIR}" \
  "${WIKI_DIR}/artifacts" \
  "${WIKI_DIR}/questions" \
  "${WIKI_DIR}/meta"

write_if_missing() {
  local target="$1"
  if [[ ! -e "${target}" ]]; then
    cat > "${target}"
  fi
}

write_csv_if_missing() {
  local target="$1"
  local header="$2"
  if [[ ! -e "${target}" ]]; then
    printf '%s\n' "${header}" > "${target}"
  fi
}

write_if_missing "${INVESTIGATION_DIR}/AGENTS.md" <<EOF
# ${INVESTIGATION_ID} Investigation Case Folder

## Purpose

This case folder is the durable analyst workspace for the
\`${INVESTIGATION_ID}\` investigation.

## Operating Rules

1. Treat the Spreadsheet of Doom under \`./spreadsheet-of-doom/\` as the
   canonical structured case record.
2. Use \`systems.csv\` to track machines in scope. Do not create one vault per
   machine when the machines belong to the same investigation.
3. Keep raw outputs under \`${EVIDENCE_DIR}/systems/<system>/\`.
4. Use the wiki for short narrative analysis, open questions, hot context, and
   artifact review routing.
5. Prefer CSV for durable structured storage. Generate XLSX later only as a
   convenience view, not as the source of truth.
6. Do not edit raw result files in the evidence directory.
7. Prefer exact paths, timestamps, hashes, flow ids, plugin names, and source
   file references.

## Iterative Analysis Loop

1. Read \`wiki/hot.md\`, \`wiki/analysis.md\`, \`wiki/investigative-questions.md\`,
   and \`wiki/spreadsheet-of-doom.md\` first.
2. Review the relevant Spreadsheet of Doom CSVs before collecting more data.
3. If an open question remains, collect only what is needed to answer it.
4. Add or update rows in the appropriate Spreadsheet of Doom CSVs.
5. Refresh the wiki so the narrative and the structured spreadsheet stay in
   sync.
EOF

write_if_missing "${WIKI_DIR}/index.md" <<EOF
---
type: meta
title: "${INVESTIGATION_ID} Investigation Index"
created: ${TODAY}
updated: ${TODAY}
tags:
  - meta
  - dfir
  - investigation
status: active
---

# ${INVESTIGATION_ID} Investigation Index

- [[analysis]]
- [[spreadsheet-of-doom]]
- [[investigative-questions]]
- [[evidence]]
- [[hot]]
- [[log]]
- [[artifacts/_index]]
- [[questions/_index]]
- [[meta/sync-status]]
EOF

write_if_missing "${WIKI_DIR}/hot.md" <<EOF
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
${NOW_ISO}. Investigation case scaffolded.

## Key Recent Facts
- Investigation: \`${INVESTIGATION_ID}\`
- Evidence path: \`${EVIDENCE_DIR}\`
- Spreadsheet of Doom root: \`${SOD_DIR}\`

## Recent Changes
- Created: [[analysis]]
- Created: [[spreadsheet-of-doom]]
- Created: [[investigative-questions]]
- Created: [[evidence]]

## Active Threads
- Initial Spreadsheet of Doom setup
EOF

write_if_missing "${WIKI_DIR}/log.md" <<EOF
---
type: meta
title: "${INVESTIGATION_ID} Investigation Log"
created: ${TODAY}
updated: ${TODAY}
tags:
  - meta
  - log
  - dfir
status: active
---

# Investigation Log

- ${NOW_ISO}: Scaffolded investigation case folder for \`${INVESTIGATION_ID}\`.
EOF

write_if_missing "${WIKI_DIR}/analysis.md" <<EOF
---
type: analysis
title: "${INVESTIGATION_ID} Analysis"
created: ${TODAY}
updated: ${TODAY}
tags:
  - analysis
  - dfir
  - investigation
status: active
---

# Analysis

## Executive Summary
- Add the current analyst position here.

## Key Findings
- 

## Open Questions
- 

## Next Actions
- 
EOF

write_if_missing "${WIKI_DIR}/spreadsheet-of-doom.md" <<EOF
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

The canonical structured case record for this investigation lives under:

- \`${SOD_DIR}\`

## Core Sheets

- [timeline.csv](../spreadsheet-of-doom/timeline.csv)
- [systems.csv](../spreadsheet-of-doom/systems.csv)
- [users.csv](../spreadsheet-of-doom/users.csv)
- [host-indicators.csv](../spreadsheet-of-doom/host-indicators.csv)
- [network-indicators.csv](../spreadsheet-of-doom/network-indicators.csv)
- [task-tracker.csv](../spreadsheet-of-doom/task-tracker.csv)
- [evidence-tracker.csv](../spreadsheet-of-doom/evidence-tracker.csv)
- [keywords.csv](../spreadsheet-of-doom/keywords.csv)
- [Workbook Export](../${INVESTIGATION_ID}_SoD.xlsx)

## Guidance

- Use \`systems.csv\` to track each host in the same investigation.
- Use the indicator sheets for atomic IOCs and noteworthy adversary-tracking
  pivots.
- Use \`task-tracker.csv\` for leads, follow-up actions, and open work.
- Use \`analysis.md\` for short narrative interpretation, not as the only case
  record.
EOF

write_if_missing "${WIKI_DIR}/investigative-questions.md" <<EOF
---
type: question
title: "${INVESTIGATION_ID} Investigative Questions"
created: ${TODAY}
updated: ${TODAY}
tags:
  - questions
  - dfir
  - investigation
status: active
---

# Investigative Questions

1. Initial Access: how did the attacker get in?
2. Execution: what did the attacker run?
3. Command And Control: was there external communication?
4. Persistence: how was access maintained?
5. Privilege Escalation And Credential Access: did they gain higher privileges
   or collect credentials?
6. Lateral Movement: where did they spread?
7. Exfiltration: what was stolen or staged for theft?
EOF

write_if_missing "${WIKI_DIR}/evidence.md" <<EOF
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

## Standard Layout
- \`${SYSTEMS_DIR}/<system>/\` for per-system raw outputs
- \`${SOD_DIR}/\` for the investigation-wide Spreadsheet of Doom

## Notes
- Browse the raw case data through the \`evidence/\` directory.
- Use [[artifacts/_index]] for generated file-level notes.
EOF

write_if_missing "${WIKI_DIR}/artifacts/_index.md" <<EOF
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

- Run the ingest skill to populate artifact notes.
EOF

write_if_missing "${WIKI_DIR}/questions/_index.md" <<EOF
---
type: meta
title: "${INVESTIGATION_ID} Questions Index"
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

write_if_missing "${WIKI_DIR}/meta/sync-status.md" <<EOF
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

- No ingestion run has been recorded yet.
EOF

write_csv_if_missing \
  "${SOD_DIR}/timeline.csv" \
  'Date/Time (UTC),System Name,Timestamp Type,Activity,Evidence,Source,Details/Comments,ATT&CK Alignment,Size (bytes),Hash,Owner/Account,Submitted By,Date Added,Status/Tag,Notes'

write_csv_if_missing \
  "${SOD_DIR}/systems.csv" \
  'Submitted By,Date Added,System Name,IP Address,Domain,System,Role,Operating System,Initial Lead,Significant Findings,Status,Earliest Evidence (UTC),Latest Evidence (UTC),Notes'

write_csv_if_missing \
  "${SOD_DIR}/users.csv" \
  'Submitted By,Date Added,Source,Account ID,Account Name,SID,Domain,Account Role,Significant Findings,Status,Earliest Evidence (UTC),Latest Evidence (UTC),Notes'

write_csv_if_missing \
  "${SOD_DIR}/host-indicators.csv" \
  'Submitted By,Date Added,Source,Status,Indicator ID,Indicator Type,Indicator,Full Path,SHA256,SHA1,MD5,Type / Purpose,Size (bytes),ATT&CK Alignment,Notes'

write_csv_if_missing \
  "${SOD_DIR}/network-indicators.csv" \
  'Submitted By,Date Added,Source,Status,Indicator ID,Indicator Type,Indicator,Initial Lead,Details/Comments,Earliest Evidence (UTC),Latest Evidence (UTC),ATT&CK Alignment,Notes'

write_csv_if_missing \
  "${SOD_DIR}/task-tracker.csv" \
  'Submitted By,Date Added,Source,Status,Indicator ID,Indicator Type,Indicator,Initial Lead,Details/Comments,Earliest Evidence (UTC),Latest Evidence (UTC),ATT&CK Alignment,Notes'

write_csv_if_missing \
  "${SOD_DIR}/evidence-tracker.csv" \
  'Evidence ID,Evidence Type,Evidence Source,Date Received,Data Received,Evidence Date (or Date Range),Evidence Location,Notes'

write_csv_if_missing \
  "${SOD_DIR}/keywords.csv" \
  'KeywordID,High Fidelity Forensic Keywords,Notes'
