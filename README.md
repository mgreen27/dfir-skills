# dfir-skills

A repository of skills (scripts and helpers) for Digital Forensics and Incident
Response (DFIR) investigations.

---

## Skills

### 1. `skills/download_dfir_tools.sh` – Download DFIR Tools

Downloads the latest versions of common open-source DFIR tools for **Linux** and
**macOS**:

| Tool | Source |
|------|--------|
| [Velociraptor](https://github.com/Velocidex/velociraptor) | Pre-built binary for Linux/macOS (amd64 & arm64) |
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | Source archive with auto pip dependency install |
| [The Sleuth Kit (TSK)](https://github.com/sleuthkit/sleuthkit) | Source tarball (Linux) / Homebrew (macOS) |

#### Usage

```bash
chmod +x skills/download_dfir_tools.sh

# Download all tools to ./dfir-tools (default)
./skills/download_dfir_tools.sh

# Download to a custom directory
./skills/download_dfir_tools.sh -d /opt/dfir

# Download only Velociraptor
./skills/download_dfir_tools.sh -t velociraptor

# Download only Volatility 3
./skills/download_dfir_tools.sh -t volatility

# Download only The Sleuth Kit
./skills/download_dfir_tools.sh -t tsk
```

**Requirements:** `curl`, `tar` (standard on Linux and macOS).

---

### 2. `skills/detect_collection.py` – Detect DFIR Collection Type

Identifies the type of DFIR artefact or collection present on disk.

Supported types:

| Type | Description |
|------|-------------|
| `live_response` | Folder containing typical live-response artefacts (process lists, network connections, services, registry exports, etc.) |
| `disk_image` | Raw or forensic disk image (`.img`, `.dd`, `.e01`, `.vmdk`, `.vhd`, `.vhdx`, `.qcow2`, `.iso`, etc.) |
| `memory_image` | Raw physical memory capture (`.mem`, `.vmem`, `.raw`, Windows PAGEDUMP, ELF core) |
| `process_dump` | Process memory / mini-dump file (`.dmp`, `.mdmp`, Windows Minidump, ELF core) |
| `mixed_folder` | Folder containing multiple collection types |
| `unknown` | Could not determine type |

Detection uses **magic bytes** (highest confidence) followed by file-extension
heuristics. Folder detection uses both content scanning and filename keyword
analysis.

#### Usage

```bash
# Inspect a single file
python3 skills/detect_collection.py /evidence/memory.mem

# Inspect a directory
python3 skills/detect_collection.py /cases/case001/

# Inspect multiple paths at once
python3 skills/detect_collection.py /evidence/disk.e01 /evidence/live_response/

# Verbose mode (show detection details)
python3 skills/detect_collection.py -v /cases/case001/

# JSON output (useful for scripting/pipelines)
python3 skills/detect_collection.py --json /evidence/
```

**Requirements:** Python 3.6+ (no third-party packages required).

---

## Planned Skills

- Additional tool downloads (as requested)
- Collection processing helpers
