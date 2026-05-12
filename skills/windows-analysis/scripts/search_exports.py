#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
TEXT_SUFFIXES = {
    ".csv",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".ps1",
    ".text",
    ".tsv",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
SKIP_PATH_PARTS = {"host-collection", "requests"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Search existing exported investigation rows before recollecting new evidence."
    )
    parser.add_argument("--investigation-id", required=True, help="Case folder name under ./investigations")
    parser.add_argument("--host", action="append", default=[], help="Limit the search to one or more systems")
    parser.add_argument(
        "--pattern",
        action="append",
        default=[],
        help="Literal substring to search for. Repeat for multiple values.",
    )
    parser.add_argument(
        "--exact-path",
        action="append",
        default=[],
        help="Windows path to search for after slash and case normalization. Repeat for multiple values.",
    )
    parser.add_argument(
        "--path-substring",
        help="Only inspect files whose relative path contains this text.",
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        help="Use case-sensitive literal matching for --pattern values.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "csv"),
        default="json",
        help="Output format for matches.",
    )
    parser.add_argument("--output", help="Optional file path for the rendered results.")
    return parser.parse_args()


def normalize_windows_text(value: str) -> str:
    return value.replace("/", "\\").lower()


def iter_system_dirs(investigation_id: str, hosts: list[str]) -> list[Path]:
    systems_root = REPO_ROOT / "investigations" / investigation_id / "evidence" / "systems"
    if not systems_root.is_dir():
        raise RuntimeError(f"Systems evidence directory not found: {systems_root}")
    if hosts:
        system_dirs = [systems_root / host for host in hosts]
        missing = [str(path.name) for path in system_dirs if not path.is_dir()]
        if missing:
            raise RuntimeError(f"Unknown host directories: {', '.join(sorted(missing))}")
        return system_dirs
    return sorted(path for path in systems_root.iterdir() if path.is_dir())


def should_search_file(path: Path, path_substring: str | None) -> bool:
    if any(part in SKIP_PATH_PARTS for part in path.parts):
        return False
    if path_substring and path_substring not in str(path):
        return False
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    if "exports" in path.parts:
        return True
    return False


def search_file(
    path: Path,
    investigation_id: str,
    host: str,
    literal_patterns: list[str],
    exact_paths: list[str],
    case_sensitive: bool,
) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    relative_path = path.relative_to(REPO_ROOT / "investigations" / investigation_id)
    normalized_exact_paths = {normalize_windows_text(item): item for item in exact_paths}

    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.rstrip("\n")
                haystack = line if case_sensitive else line.lower()

                for pattern in literal_patterns:
                    candidate = pattern if case_sensitive else pattern.lower()
                    if candidate in haystack:
                        matches.append(
                            {
                                "investigation_id": investigation_id,
                                "host": host,
                                "relative_file": str(relative_path),
                                "line_number": line_number,
                                "match_type": "literal",
                                "pattern": pattern,
                                "line": line,
                            }
                        )

                normalized_line = normalize_windows_text(line)
                for normalized_exact_path, original_exact_path in normalized_exact_paths.items():
                    if normalized_exact_path in normalized_line:
                        matches.append(
                            {
                                "investigation_id": investigation_id,
                                "host": host,
                                "relative_file": str(relative_path),
                                "line_number": line_number,
                                "match_type": "exact_path",
                                "pattern": original_exact_path,
                                "line": line,
                            }
                        )
    except OSError as exc:
        matches.append(
            {
                "investigation_id": investigation_id,
                "host": host,
                "relative_file": str(relative_path),
                "line_number": 0,
                "match_type": "error",
                "pattern": "",
                "line": f"Failed to read file: {exc}",
            }
        )
    return matches


def render_csv(rows: list[dict[str, object]]) -> str:
    fieldnames = ["investigation_id", "host", "relative_file", "line_number", "match_type", "pattern", "line"]
    from io import StringIO

    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({name: row.get(name, "") for name in fieldnames})
    return buffer.getvalue()


def main() -> int:
    args = parse_args()
    if not args.pattern and not args.exact_path:
        print("At least one --pattern or --exact-path value is required.", file=sys.stderr)
        return 1

    system_dirs = iter_system_dirs(args.investigation_id, args.host)
    all_matches: list[dict[str, object]] = []

    for system_dir in system_dirs:
        for path in sorted(system_dir.rglob("*")):
            if not path.is_file():
                continue
            if not should_search_file(path, args.path_substring):
                continue
            all_matches.extend(
                search_file(
                    path,
                    args.investigation_id,
                    system_dir.name,
                    args.pattern,
                    args.exact_path,
                    args.case_sensitive,
                )
            )

    all_matches.sort(key=lambda row: (str(row["host"]), str(row["relative_file"]), int(row["line_number"])))

    if args.format == "csv":
        rendered = render_csv(all_matches)
    else:
        rendered = json.dumps(all_matches, indent=2) + "\n"

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
