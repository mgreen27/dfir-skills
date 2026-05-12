#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
WINDOWS_COLLECTION = REPO_ROOT / "skills" / "windows-collection" / "scripts" / "run_windows_collection.py"


def run_collection_helper(args: list[str]) -> int:
    proc = subprocess.run(
        [sys.executable, str(WINDOWS_COLLECTION), *args],
        text=True,
        capture_output=True,
    )
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    return proc.returncode


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compatibility wrapper for the retired bulk host-collection helper. "
            "New workflows should use windows-collection directly."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    queue_cmd = subparsers.add_parser("queue", help="Route collection requests to windows-collection")
    queue_cmd.add_argument("--investigation-id", required=True)
    queue_cmd.add_argument("--host", required=True)
    queue_cmd.add_argument("--collection-type", choices=("all", "execution"))
    queue_cmd.add_argument("--artifact", action="append", default=[])
    queue_cmd.add_argument("--env", action="append", default=[])
    queue_cmd.add_argument("--timeout-seconds", type=int, default=60)
    queue_cmd.add_argument("--poll-interval-seconds", type=int, default=15)
    queue_cmd.add_argument("--poll-timeout-seconds", type=int, default=3600)
    queue_cmd.add_argument("--no-poll", action="store_true")

    status_cmd = subparsers.add_parser("status", help="Route status checks to windows-collection")
    status_cmd.add_argument("--investigation-id", required=True)
    status_cmd.add_argument("--host", required=True)
    status_cmd.add_argument("--flow-id")

    fetch_cmd = subparsers.add_parser("fetch", help="Retired. Use export helpers instead.")
    fetch_cmd.add_argument("--investigation-id", required=True)
    fetch_cmd.add_argument("--host", required=True)
    fetch_cmd.add_argument("--flow-id")
    fetch_cmd.add_argument("--include-requested-when-empty", action="store_true")

    return parser.parse_args()


def main() -> int:
    if not WINDOWS_COLLECTION.exists():
        print(f"windows-collection helper not found at {WINDOWS_COLLECTION}", file=sys.stderr)
        return 1

    args = parse_args()
    if args.command == "queue":
        forwarded = [
            "queue",
            "--investigation-id",
            args.investigation_id,
            "--host",
            args.host,
            "--timeout-seconds",
            str(args.timeout_seconds),
            "--poll-interval-seconds",
            str(args.poll_interval_seconds),
            "--poll-timeout-seconds",
            str(args.poll_timeout_seconds),
        ]
        if args.no_poll:
            forwarded.append("--no-poll")
        if args.collection_type:
            forwarded.extend(["--collection-type", args.collection_type])
        if args.artifact:
            for artifact in args.artifact:
                forwarded.extend(["--artifact", artifact])
        for env_item in args.env:
            forwarded.extend(["--env", env_item])
        if not args.collection_type and not args.artifact:
            forwarded.extend(["--collection-type", "all"])
        return run_collection_helper(forwarded)

    if args.command == "status":
        if args.flow_id:
            print(
                json.dumps(
                    {
                        "error": "flow_id_override_not_supported",
                        "message": (
                            "The retired bulk helper no longer supports --flow-id. "
                            "Use ./skills/windows-collection/scripts/run_windows_collection.py status directly."
                        ),
                    },
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 1
        return run_collection_helper(
            ["status", "--investigation-id", args.investigation_id, "--host", args.host]
        )

    print(
        json.dumps(
            {
                "error": "bulk_fetch_retired",
                "message": (
                    "Bulk fetch is retired. Use windows-collection status plus the "
                    "collection metadata in host-collection/, then retrieve results with "
                    "your chosen artifact-specific export workflow."
                ),
            },
            indent=2,
        ),
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
