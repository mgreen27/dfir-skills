---
name: detect-dfir-collection-type
description: Detect the DFIR collection type for a file or folder. Use when you need to classify evidence as a disk image, memory image, process dump, live-response collection, mixed folder, or unknown artefact set.
---

# Detect DFIR Collection Type

Run `scripts/detect_collection.py` to classify a file or directory before
triage, sorting, or downstream analysis.

## Workflow

1. Pass one or more evidence paths to `scripts/detect_collection.py`.
2. Use `-v` when you need the matching details.
3. Use `--json` when another script or pipeline needs structured output.

## Commands

Inspect a single file:

```bash
python3 ./skills/detect-dfir-collection-type/scripts/detect_collection.py /evidence/memory.mem
```

Inspect a directory:

```bash
python3 ./skills/detect-dfir-collection-type/scripts/detect_collection.py /cases/case001
```

Inspect multiple paths with details:

```bash
python3 ./skills/detect-dfir-collection-type/scripts/detect_collection.py -v /cases/case001 /evidence/disk.e01
```

Emit JSON:

```bash
python3 ./skills/detect-dfir-collection-type/scripts/detect_collection.py --json /evidence
```

## Notes

- Prefer magic-byte signatures over extensions when both are available.
- Scan directories for recognised artefacts and live-response filename patterns.
- Return `mixed_folder` when multiple collection types are found together.
