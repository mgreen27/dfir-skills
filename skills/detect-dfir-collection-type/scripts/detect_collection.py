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
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

DISK_IMAGE_EXTENSIONS = {
    ".img", ".dd", ".raw", ".vmdk", ".vhd", ".vhdx",
    ".e01", ".ex01", ".l01", ".lx01",
    ".qcow", ".qcow2", ".iso",
}

MEMORY_IMAGE_EXTENSIONS = {".mem", ".vmem", ".raw", ".bin", ".dmp"}

PROCESS_DUMP_EXTENSIONS = {".dmp", ".mdmp", ".core"}

MAGIC_SIGNATURES = [
    (0x1FE, b"\x55\xAA", "MBR disk image (raw/dd)"),
    (0, b"\x45\x57\x46\x32", "EWF/E01 disk image"),
    (0, b"\x45\x56\x46\x09\x0D\x0A\xFF\x00", "EWF/E01 disk image"),
    (0, b"\x51\x46\x49\xFB", "QCOW2 disk image"),
    (0, b"\x4B\x44\x4D", "VMDK disk image"),
    (0, b"\x63\x6F\x6E\x65\x63\x74\x69\x78", "VMDK sparse extent"),
    (0, b"\x76\x68\x64", "VHD/VHDX disk image"),
    (0, b"\x78\x6C\x76\x68\x64", "VHDX disk image"),
    (0, b"\x4D\x53\x57\x49\x4D\x00\x00\x00", "WIM image"),
    (0, b"\x50\x41\x47\x45\x44\x55\x4D\x50", "Windows full/kernel memory dump (PAGEDUMP)"),
    (0, b"\x44\x55\x4D\x50", "Windows memory dump (DUMP)"),
    (0, b"\x45\x4C\x46\x41\x44\x4D\x50\x42", "ELF core (Linux memory)"),
    (0, b"\x4D\x44\x4D\x50\x93\xA7", "Windows Minidump (.mdmp)"),
    (0, b"\x7F\x45\x4C\x46", "ELF core / process dump"),
]

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

LIVE_RESPONSE_KEYWORDS = {
    "process", "processes", "proc", "netstat", "network", "connections",
    "services", "service", "tasks", "scheduled",
    "autoruns", "autorun", "registry", "reg", "prefetch", "users",
    "accounts", "groups", "shares", "dns", "routes", "arp", "firewall",
    "environ", "environment", "hostname", "sysinfo", "system",
    "installedapps", "software", "startup", "drivers", "modules",
}


@dataclass
class CollectionResult:
    path: str
    collection_type: str
    description: str
    confidence: str
    details: List[str] = field(default_factory=list)


def _read_bytes(path: Path, offset: int, length: int) -> bytes:
    try:
        with open(path, "rb") as fh:
            fh.seek(offset)
            return fh.read(length)
    except OSError:
        return b""


def _check_magic(path: Path) -> Optional[str]:
    for offset, magic, description in MAGIC_SIGNATURES:
        data = _read_bytes(path, offset, len(magic))
        if data == magic:
            return description
    return None


def _magic_category(description: str) -> Optional[str]:
    if description in _DISK_LABELS:
        return "disk_image"
    if description in _MEMORY_LABELS:
        return "memory_image"
    if description in _PROCESS_LABELS:
        return "process_dump"
    return None


def _score_live_response(folder: Path) -> int:
    score = 0
    try:
        for entry in os.scandir(folder):
            stem = Path(entry.name).stem.lower()
            for keyword in LIVE_RESPONSE_KEYWORDS:
                if keyword in stem:
                    score += 1
                    break
    except PermissionError:
        pass
    return score


def detect_file(path: Path) -> CollectionResult:
    ext = path.suffix.lower()
    details: List[str] = []

    magic_desc = _check_magic(path)
    if magic_desc:
        category = _magic_category(magic_desc)
        if category:
            details.append(f"Magic bytes match: {magic_desc}")
            return CollectionResult(
                path=str(path),
                collection_type=category,
                description=magic_desc,
                confidence="high",
                details=details,
            )

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

    return CollectionResult(
        path=str(path),
        collection_type="unknown",
        description="Could not determine collection type",
        confidence="low",
        details=details,
    )


def detect_folder(path: Path) -> CollectionResult:
    details: List[str] = []

    try:
        entries = list(os.scandir(path))
    except PermissionError:
        return CollectionResult(
            path=str(path),
            collection_type="unknown",
            description="Permission denied reading directory",
            confidence="low",
        )

    found_types: Dict[str, List[str]] = {}

    for entry in entries:
        if entry.is_file(follow_symlinks=False):
            result = detect_file(Path(entry.path))
            if result.collection_type != "unknown":
                found_types.setdefault(result.collection_type, []).append(entry.name)

    lr_score = _score_live_response(path)
    if lr_score >= 3:
        found_types.setdefault("live_response", []).append(f"(keyword score: {lr_score})")

    if len(found_types) == 0:
        sub_types: Dict[str, List[str]] = {}
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                sub_result = detect_folder(Path(entry.path))
                if sub_result.collection_type != "unknown":
                    sub_types.setdefault(sub_result.collection_type, []).append(entry.name)
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
        collection_type = next(iter(found_types))
        files = found_types[collection_type]
        details.append(
            f"Found {len(files)} file(s) of type '{collection_type}': "
            + ", ".join(files[:5])
            + (" ..." if len(files) > 5 else "")
        )
        return CollectionResult(
            path=str(path),
            collection_type=collection_type,
            description=f"Folder containing {collection_type} artefacts",
            confidence="high" if collection_type == "live_response" and lr_score >= 5 else "medium",
            details=details,
        )

    for collection_type, files in found_types.items():
        details.append(
            f"  [{collection_type}] {len(files)} file(s): "
            + ", ".join(files[:3])
            + (" ..." if len(files) > 3 else "")
        )

    return CollectionResult(
        path=str(path),
        collection_type="mixed_folder",
        description="Folder containing multiple DFIR collection types",
        confidence="high",
        details=details,
    )


def detect(path_str: str) -> CollectionResult:
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


def _colour(text: str, code: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


TYPE_COLOURS = {
    "live_response": "32",
    "disk_image": "34",
    "memory_image": "35",
    "process_dump": "33",
    "mixed_folder": "36",
    "unknown": "31",
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
        "-v",
        "--verbose",
        action="store_true",
        help="Show extra details about detection",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    args = parser.parse_args()

    results = [detect(path) for path in args.paths]

    if args.json:
        import json

        output = [
            {
                "path": result.path,
                "collection_type": result.collection_type,
                "description": result.description,
                "confidence": result.confidence,
                "details": result.details,
            }
            for result in results
        ]
        print(json.dumps(output, indent=2))
    else:
        for result in results:
            print_result(result, verbose=args.verbose)
        print()

    return 1 if any(result.collection_type == "unknown" for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())
