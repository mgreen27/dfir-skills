#!/usr/bin/env python3
"""
detect_collection.py
====================
Detect the type of DFIR collection present on disk.

Supported collection types:
  - live_response   : Folder containing typical live-response artefacts
                      (process lists, network connections, service listings, etc.)
  - disk_image      : Raw or forensic disk image
                      (.img, .dd, .raw, .vmdk, .vhd, .vhdx, .e01, .ex01, .qcow2, .iso)
  - memory_image    : Raw physical memory capture
                      (.mem, .vmem, .raw, .bin)
  - process_dump    : Process memory / mini-dump file
                      (.dmp, .mdmp, .core)
  - mixed_folder    : Folder that contains multiple collection types
  - unknown         : Unrecognised target

Usage:
    python3 detect_collection.py <path> [<path> ...]
    python3 detect_collection.py --help

Examples:
    python3 detect_collection.py /cases/case001
    python3 detect_collection.py /evidence/memory.mem /evidence/disk.e01
"""

import argparse
import os
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# File-extension sets
# ---------------------------------------------------------------------------
DISK_IMAGE_EXTENSIONS = {
    ".img", ".dd", ".raw", ".vmdk", ".vhd", ".vhdx",
    ".e01", ".ex01", ".l01", ".lx01",
    ".qcow", ".qcow2", ".iso",
}

# Raw memory extensions overlap with .raw – magic bytes break the tie.
MEMORY_IMAGE_EXTENSIONS = {".mem", ".vmem", ".raw", ".bin", ".dmp"}

PROCESS_DUMP_EXTENSIONS = {".dmp", ".mdmp", ".core"}

# ---------------------------------------------------------------------------
# Magic byte signatures (offset, bytes) → label
# ---------------------------------------------------------------------------
# Each entry: (file_offset, magic_bytes, description)
MAGIC_SIGNATURES = [
    # ---- Disk images ---------------------------------------------------------
    (0x1FE, b"\x55\xAA",               "MBR disk image (raw/dd)"),
    (0,     b"\x45\x57\x46\x32",       "EWF/E01 disk image"),          # EWF2
    (0,     b"\x45\x56\x46\x09\x0D\x0A\xFF\x00",
                                        "EWF/E01 disk image"),          # EWFv1
    (0,     b"\x51\x46\x49\xFB",       "QCOW2 disk image"),
    (0,     b"\x4B\x44\x4D",           "VMDK disk image"),
    (0,     b"\x63\x6F\x6E\x65\x63\x74\x69\x78",
                                        "VMDK sparse extent"),
    (0,     b"\x76\x68\x64",           "VHD/VHDX disk image"),
    (0,     b"\x78\x6C\x76\x68\x64",   "VHDX disk image"),
    (0,     b"\x4D\x53\x57\x49\x4D\x00\x00\x00",
                                        "WIM image"),
    # ---- Memory images -------------------------------------------------------
    (0,     b"\x50\x41\x47\x45\x44\x55\x4D\x50",
                                        "Windows full/kernel memory dump (PAGEDUMP)"),
    (0,     b"\x44\x55\x4D\x50",       "Windows memory dump (DUMP)"),
    (0,     b"\x45\x4C\x46\x41\x44\x4D\x50\x42",
                                        "ELF core (Linux memory)"),
    # ---- Process / mini-dumps ------------------------------------------------
    (0,     b"\x4D\x44\x4D\x50\x93\xA7",
                                        "Windows Minidump (.mdmp)"),
    (0,     b"\x7F\x45\x4C\x46",       "ELF core / process dump"),
]

# Labels that belong to each category (must match MAGIC_SIGNATURES descriptions exactly)
_DISK_LABELS = {
    "MBR disk image (raw/dd)",
    "EWF/E01 disk image",
    "EWF Legacy",
    "QCOW2 disk image",
    "VMDK disk image",
    "VMDK sparse extent",
    "VHD/VHDX disk image",
    "VHDX disk image",
    "WIM image",
}
_MEMORY_LABELS = {
    "Windows full/kernel memory dump (PAGEDUMP)",
    "Windows memory dump (DUMP)",
    "ELF core (Linux memory)",
}
_PROCESS_LABELS = {
    "Windows Minidump (.mdmp)",
    "ELF core / process dump",
}

# ---------------------------------------------------------------------------
# Live-response folder heuristics
# ---------------------------------------------------------------------------
# If a folder contains files whose names include any of these keywords we
# consider it a live-response collection.
LIVE_RESPONSE_KEYWORDS = {
    "process", "processes", "proc", "netstat", "network", "connections",
    "services", "service", "tasks", "scheduled",
    "autoruns", "autorun", "registry", "reg", "prefetch", "users",
    "accounts", "groups", "shares", "dns", "routes", "arp", "firewall",
    "environ", "environment", "hostname", "sysinfo", "system",
    "installedapps", "software", "startup", "drivers", "modules",
}


# ---------------------------------------------------------------------------
# Result data class
# ---------------------------------------------------------------------------
@dataclass
class CollectionResult:
    path: str
    collection_type: str
    description: str
    confidence: str          # high / medium / low
    details: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_bytes(path: Path, offset: int, length: int) -> bytes:
    """Read *length* bytes from *path* at *offset*, returning b'' on error."""
    try:
        with open(path, "rb") as fh:
            fh.seek(offset)
            return fh.read(length)
    except OSError:
        return b""


def _check_magic(path: Path) -> Optional[str]:
    """Return the first matching magic-byte description or None."""
    for offset, magic, description in MAGIC_SIGNATURES:
        data = _read_bytes(path, offset, len(magic))
        if data == magic:
            return description
    return None


def _magic_category(description: str) -> Optional[str]:
    """Map a magic description to a collection category."""
    if description in _DISK_LABELS:
        return "disk_image"
    if description in _MEMORY_LABELS:
        return "memory_image"
    if description in _PROCESS_LABELS:
        return "process_dump"
    return None


def _score_live_response(folder: Path) -> int:
    """Return a keyword hit count for live-response folder detection."""
    score = 0
    try:
        for entry in os.scandir(folder):
            stem = Path(entry.name).stem.lower()
            # Exact match or keyword contained in filename stem
            for kw in LIVE_RESPONSE_KEYWORDS:
                if kw in stem:
                    score += 1
                    break
    except PermissionError:
        pass
    return score


# ---------------------------------------------------------------------------
# Core detection logic
# ---------------------------------------------------------------------------

def detect_file(path: Path) -> CollectionResult:
    """Detect the collection type of a single *file*."""
    ext = path.suffix.lower()
    details: List[str] = []

    # 1. Magic bytes take priority
    magic_desc = _check_magic(path)
    if magic_desc:
        cat = _magic_category(magic_desc)
        if cat:
            details.append(f"Magic bytes match: {magic_desc}")
            return CollectionResult(
                path=str(path),
                collection_type=cat,
                description=magic_desc,
                confidence="high",
                details=details,
            )

    # 2. Fall back to extension hints
    if ext in DISK_IMAGE_EXTENSIONS:
        details.append(f"Extension matches disk image set: {ext}")
        return CollectionResult(
            path=str(path),
            collection_type="disk_image",
            description=f"Disk image (extension: {ext})",
            confidence="medium",
            details=details,
        )

    if ext in PROCESS_DUMP_EXTENSIONS:
        details.append(f"Extension matches process dump set: {ext}")
        return CollectionResult(
            path=str(path),
            collection_type="process_dump",
            description=f"Process/minidump file (extension: {ext})",
            confidence="medium",
            details=details,
        )

    if ext in MEMORY_IMAGE_EXTENSIONS:
        details.append(f"Extension matches memory image set: {ext}")
        return CollectionResult(
            path=str(path),
            collection_type="memory_image",
            description=f"Memory image (extension: {ext})",
            confidence="medium",
            details=details,
        )

    # 3. Unknown
    return CollectionResult(
        path=str(path),
        collection_type="unknown",
        description="Could not determine collection type",
        confidence="low",
        details=details,
    )


def detect_folder(path: Path) -> CollectionResult:
    """Detect the collection type of a *directory*."""
    details: List[str] = []

    # Gather types of files found inside
    found_types: dict = {}
    try:
        entries = list(os.scandir(path))
    except PermissionError:
        return CollectionResult(
            path=str(path),
            collection_type="unknown",
            description="Permission denied reading directory",
            confidence="low",
        )

    for entry in entries:
        if entry.is_file(follow_symlinks=False):
            result = detect_file(Path(entry.path))
            if result.collection_type != "unknown":
                found_types.setdefault(result.collection_type, []).append(entry.name)

    # Check for live-response keywords in filenames
    lr_score = _score_live_response(path)
    if lr_score >= 3:
        found_types.setdefault("live_response", []).append(
            f"(keyword score: {lr_score})"
        )

    if len(found_types) == 0:
        # Recurse one level to catch sub-folder collections
        sub_types: dict = {}
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                sub_result = detect_folder(Path(entry.path))
                if sub_result.collection_type not in ("unknown",):
                    sub_types.setdefault(sub_result.collection_type, []).append(
                        entry.name
                    )
        if sub_types:
            found_types = sub_types
            details.append("Collection types detected in sub-directories")

    if len(found_types) == 0:
        return CollectionResult(
            path=str(path),
            collection_type="unknown",
            description="No recognisable DFIR collection found in folder",
            confidence="low",
            details=details,
        )

    if len(found_types) == 1:
        col_type = next(iter(found_types))
        files = found_types[col_type]
        details.append(
            f"Found {len(files)} file(s) of type '{col_type}': "
            + ", ".join(files[:5])
            + (" …" if len(files) > 5 else "")
        )
        return CollectionResult(
            path=str(path),
            collection_type=col_type,
            description=f"Folder containing {col_type} artefacts",
            confidence="high" if col_type == "live_response" and lr_score >= 5 else "medium",
            details=details,
        )

    # Multiple types found → mixed folder
    for col_type, files in found_types.items():
        details.append(
            f"  [{col_type}] {len(files)} file(s): "
            + ", ".join(files[:3])
            + (" …" if len(files) > 3 else "")
        )
    return CollectionResult(
        path=str(path),
        collection_type="mixed_folder",
        description="Folder containing multiple DFIR collection types",
        confidence="high",
        details=details,
    )


def detect(path_str: str) -> CollectionResult:
    """Entry point: detect the collection type at *path_str*."""
    path = Path(path_str)

    if not path.exists():
        return CollectionResult(
            path=path_str,
            collection_type="unknown",
            description=f"Path does not exist: {path_str}",
            confidence="low",
        )

    if path.is_dir():
        return detect_folder(path)
    return detect_file(path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _colour(text: str, code: str) -> str:
    """Wrap *text* in ANSI escape if stdout is a TTY."""
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


TYPE_COLOURS = {
    "live_response": "32",   # green
    "disk_image":    "34",   # blue
    "memory_image":  "35",   # magenta
    "process_dump":  "33",   # yellow
    "mixed_folder":  "36",   # cyan
    "unknown":       "31",   # red
}


def print_result(result: CollectionResult, verbose: bool = False) -> None:
    colour = TYPE_COLOURS.get(result.collection_type, "0")
    type_str = _colour(result.collection_type.upper(), colour)
    conf_str = _colour(f"[{result.confidence}]", "1")

    print(f"\nPath        : {result.path}")
    print(f"Type        : {type_str}")
    print(f"Description : {result.description}")
    print(f"Confidence  : {conf_str}")

    if verbose and result.details:
        print("Details     :")
        for line in result.details:
            print(f"  {line}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="+",
        metavar="PATH",
        help="File or directory to inspect",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show extra details about detection",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    args = parser.parse_args()

    results = [detect(p) for p in args.paths]

    if args.json:
        import json
        output = [
            {
                "path":            r.path,
                "collection_type": r.collection_type,
                "description":     r.description,
                "confidence":      r.confidence,
                "details":         r.details,
            }
            for r in results
        ]
        print(json.dumps(output, indent=2))
    else:
        for result in results:
            print_result(result, verbose=args.verbose)
        print()

    # Exit non-zero if any path is unknown
    return 1 if any(r.collection_type == "unknown" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
