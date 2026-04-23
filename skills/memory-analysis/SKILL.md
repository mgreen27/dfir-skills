---
name: memory-analysis
description: Run Volatility 3 memory triage against a Windows memory image using the repo-local tooling and write text outputs into the repo investigation folder. Use when you need memory-image triage, process review, command-line review, network connection review, malfind review, or a repeatable Volatility workflow tied to an investigation.
---

# Memory Analysis

Use the commands below from the repo root to triage a Windows memory image with
the repo-local Volatility 3 checkout.

## Workflow

1. Confirm the memory image path.
2. Create or reuse
   `./investigations/<investigation-name>/evidence/systems/<system>/volatility3/`.
3. Create or reuse `./volatility3-cache/` before running Volatility commands.
4. Create or reuse the matching investigation wiki under
   `./investigations/<investigation-name>/wiki/`.
5. Keep iterative analysis in the investigation wiki, not flat case markdown
   files.
6. Prefer `.txt` outputs for Volatility results so they are easy to grep,
   chunk, and re-review.
7. Use `--offline` and a repo-local `--cache-path` for repeatable runs.
8. Start with `windows.info`, `windows.pslist`, `windows.pstree`,
   `windows.cmdline`, `windows.psscan`, `windows.netscan`, and
   `windows.malfind`.
9. If a plugin can dump content, set `-o` to a case-local dump folder.
10. If `windows.psscan` works but `windows.pslist` fails or is sparse, treat
   scan-based plugins as the more reliable source for that image.
11. When plugin behavior is inconsistent, rerun with `-vvv` to check for page
    faults, smear, or other image-read issues.
12. After each memory collection step, update the investigation wiki with what
    was answered and what still needs clarification.
13. In a first-pass DFIR review, record potentially malicious memory-resident
    processes, command lines, network artefacts, or injected regions in
    `wiki/suspicious-artifacts.md` before they are fully resolved.

## Analyst Lens

When updating the investigation wiki findings, use this lens:

You are a senior DFIR analyst. Be technically precise, evidence-driven, and
skeptical of weak signals. Review the supplied investigation notes, result
files, and artifact outputs with close attention to execution evidence,
timeline consistency, user context, persistence, credential access, lateral
movement, defense evasion, and data staging or exfiltration. Separate
confirmed findings from leads and noise. For each notable item, explain why it
matters, what artifact supports it, how strong the evidence is, and what the
most likely benign explanation would be. Do not overclaim. Produce a concise
analyst narrative with: executive summary, key findings, confidence, gaps, and
next investigative actions. Prefer exact paths, timestamps, usernames,
hostnames, process names, command lines, IPs, ports, and plugin names. If
evidence is insufficient, say so clearly.

## Commands

Set reusable shell variables first:

```bash
INVESTIGATION_ID=shieldbase-intrusion
SYSTEM_NAME=base-dc
MEMORY_IMAGE=/Users/matt/git/dfir-skills/data/base-dc-memory.img
mkdir -p /Users/matt/git/dfir-skills/volatility3-cache
mkdir -p "/Users/matt/git/dfir-skills/investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/volatility3/dumps"
/Users/matt/git/dfir-skills/skills/investigation/scripts/init_investigation.sh "$INVESTIGATION_ID"
```

Collect basic OS and kernel details:

```bash
cd /Users/matt/git/dfir-skills
./venv/bin/python ./volatility3/vol.py -f "$MEMORY_IMAGE" \
  --offline \
  --cache-path ./volatility3-cache \
  -r pretty \
  windows.info \
  > "./investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/volatility3/windows.info.txt"
```

List processes:

```bash
cd /Users/matt/git/dfir-skills
./venv/bin/python ./volatility3/vol.py -f "$MEMORY_IMAGE" \
  --offline \
  --cache-path ./volatility3-cache \
  -r pretty \
  windows.pslist \
  > "./investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/volatility3/windows.pslist.txt"
```

Recover processes with the scan-based plugin:

```bash
cd /Users/matt/git/dfir-skills
./venv/bin/python ./volatility3/vol.py -f "$MEMORY_IMAGE" \
  --offline \
  --cache-path ./volatility3-cache \
  -r pretty \
  windows.psscan \
  > "./investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/volatility3/windows.psscan.txt"
```

Show the process tree:

```bash
cd /Users/matt/git/dfir-skills
./venv/bin/python ./volatility3/vol.py -f "$MEMORY_IMAGE" \
  --offline \
  --cache-path ./volatility3-cache \
  -r pretty \
  windows.pstree \
  > "./investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/volatility3/windows.pstree.txt"
```

Collect command lines:

```bash
cd /Users/matt/git/dfir-skills
./venv/bin/python ./volatility3/vol.py -f "$MEMORY_IMAGE" \
  --offline \
  --cache-path ./volatility3-cache \
  -r pretty \
  windows.cmdline \
  > "./investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/volatility3/windows.cmdline.txt"
```

Review network sockets:

```bash
cd /Users/matt/git/dfir-skills
./venv/bin/python ./volatility3/vol.py -f "$MEMORY_IMAGE" \
  --offline \
  --cache-path ./volatility3-cache \
  -r pretty \
  windows.netscan \
  > "./investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/volatility3/windows.netscan.txt"
```

## Diagnostics

If `windows.psscan` works and `windows.pslist` fails, keep using the scan-based
plugins and collect debug output with `-vvv`.

Minimal diagnostic examples using the direct repo paths:

```bash
python volatility3/vol.py -f data/base-dc-memory.img windows.psscan
python volatility3/vol.py -f data/base-dc-memory.img windows.pslist
python volatility3/vol.py -f data/base-dc-memory.img -vvv windows.psscan
python volatility3/vol.py -f data/base-dc-memory.img windows.netscan
```

Repo-local equivalents with the prepared venv:

```bash
cd /Users/matt/git/dfir-skills
./venv/bin/python ./volatility3/vol.py -f "$MEMORY_IMAGE" \
  --offline \
  --cache-path ./volatility3-cache \
  -vvv \
  windows.psscan \
  > "./investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/volatility3/windows.psscan.vvv.txt" \
  2> "./investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/volatility3/windows.psscan.vvv.err"
```

Interpretation guidance:

- If `psscan` returns useful rows while `pslist` is empty, do not treat the
  empty `pslist` as proof that no processes are present.
- `windows.netscan` is often still worth running because it scans memory
  structures directly, but page-fault or smear errors should be recorded in
  the investigation wiki.
- Capture `stderr` when using `-vvv` so image-read issues are preserved with
  the case outputs.

Review suspicious injected memory regions and dump them:

```bash
cd /Users/matt/git/dfir-skills
./venv/bin/python ./volatility3/vol.py -f "$MEMORY_IMAGE" \
  --offline \
  --cache-path ./volatility3-cache \
  -r pretty \
  -o "./investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/volatility3/dumps" \
  windows.malfind --dump \
  > "./investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/volatility3/windows.malfind.txt"
```

Target a specific process later if needed:

```bash
cd /Users/matt/git/dfir-skills
./venv/bin/python ./volatility3/vol.py -f "$MEMORY_IMAGE" \
  --offline \
  --cache-path ./volatility3-cache \
  -r pretty \
  windows.dlllist --pid 1234 \
  > "./investigations/${INVESTIGATION_ID}/evidence/systems/${SYSTEM_NAME}/volatility3/windows.dlllist.pid-1234.txt"
```

## Notes

- This skill expects Volatility 3 to be staged under `./volatility3/`.
- Use `./venv/bin/python` by default so the repo-local dependencies are used.
- Prefer text output files for memory triage unless a later workflow requires
  `json` or `jsonl`.
- Keep dumped artifacts inside the investigation-specific `dumps/` folder.
- After refreshing memory outputs, run the investigation-ingest skill so
  the investigation `wiki/` folder stays current.
- Use open questions in the wiki to decide the next memory plugin to run rather
  than collecting blindly.
