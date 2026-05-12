#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
WINDOWS_COLLECTION = REPO_ROOT / "skills" / "windows-collection" / "scripts" / "run_windows_collection.py"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Wrapper for live remote Velociraptor collection. "
            "Forwards to windows-collection with an explicit API client config."
        )
    )
    parser.add_argument(
        "--api-client",
        required=True,
        help="Path to the live remote Velociraptor api_client.yaml to use.",
    )
    parser.add_argument(
        "--org-id",
        default="root",
        help="Velociraptor org id to use for the live remote environment.",
    )
    parser.add_argument(
        "forwarded",
        nargs=argparse.REMAINDER,
        help="windows-collection command and arguments to forward.",
    )
    return parser.parse_args()


def main() -> int:
    if not WINDOWS_COLLECTION.exists():
        print(f"windows-collection helper not found at {WINDOWS_COLLECTION}", file=sys.stderr)
        return 1

    args = parse_args()
    forwarded = list(args.forwarded)
    if forwarded and forwarded[0] == "--":
        forwarded = forwarded[1:]
    if not forwarded:
        print("Pass a windows-collection subcommand to forward, for example: ensure --investigation-id ...", file=sys.stderr)
        return 1

    proc = subprocess.run(
        [
            sys.executable,
            str(WINDOWS_COLLECTION),
            *forwarded,
            "--api-client",
            args.api_client,
            "--org-id",
            args.org_id,
        ],
        text=True,
        capture_output=True,
    )
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
