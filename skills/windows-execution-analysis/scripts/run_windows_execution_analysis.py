#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
VELO_DIR = REPO_ROOT / "velociraptor"
VELO_BIN = VELO_DIR / "velociraptor"
API_CLIENT = VELO_DIR / "api_client.yaml"
ORG_ID = "root"
ARTIFACTS = (
    "Windows.Detection.Amcache",
    "Windows.Forensics.Bam",
    "Windows.Forensics.Timeline",
    "Windows.Registry.UserAssist",
    "Windows.Registry.AppCompatCache",
    "Windows.System.AppCompatPCA",
    "Windows.Forensics.Prefetch",
)
OPEN_STATES = {"RUNNING", "IN_PROGRESS", "WAITING", "QUEUED"}


@dataclass
class ClientRecord:
    client_id: str
    hostname: str
    last_seen: str


@dataclass
class FlowRecord:
    session_id: str
    state: str
    total_rows: int
    created: str


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def slugify(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in value).strip("-").replace("--", "-")


def run_cmd(args: list[str], *, capture: bool = True, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        check=True,
        text=True,
        capture_output=capture,
    )


def velo_query(vql: str, fmt: str = "json") -> Any:
    proc = run_cmd(
        [
            str(VELO_BIN),
            "-a",
            str(API_CLIENT),
            "--runas",
            "api",
            "query",
            "--format",
            fmt,
            vql,
        ],
        cwd=VELO_DIR,
    )
    if fmt == "json":
        return json.loads(proc.stdout)
    return proc.stdout


def get_client(hostname: str) -> ClientRecord:
    rows = velo_query(
        "SELECT client_id, os_info.hostname as Hostname, "
        "timestamp(epoch=last_seen_at) as LastSeen "
        f"FROM clients() WHERE os_info.hostname =~ '^{hostname}$' "
        f"OR os_info.fqdn =~ '^{hostname}$' ORDER BY last_seen_at DESC"
    )
    if not rows:
        raise RuntimeError(f"No Velociraptor client found for hostname {hostname}")
    row = rows[0]
    return ClientRecord(
        client_id=row["client_id"],
        hostname=row.get("Hostname") or hostname,
        last_seen=row.get("LastSeen", ""),
    )


def get_flows(client_id: str, artifact: str) -> list[FlowRecord]:
    rows = velo_query(
        "SELECT session_id, state, total_collected_rows, "
        "timestamp(epoch=create_time) as Created "
        f"FROM flows(client_id='{client_id}') "
        f"WHERE request.specs[0].artifact = '{artifact}' "
        "ORDER BY create_time DESC"
    )
    flows: list[FlowRecord] = []
    for row in rows:
        flows.append(
            FlowRecord(
                session_id=row["session_id"],
                state=(row.get("state") or "").upper(),
                total_rows=int(row.get("total_collected_rows") or 0),
                created=row.get("Created", ""),
            )
        )
    return flows


def pick_finished_flow(flows: list[FlowRecord]) -> FlowRecord | None:
    for flow in flows:
        if flow.state == "FINISHED":
            return flow
    return None


def queue_artifact(client_id: str, artifact: str) -> str:
    existing_ids = {flow.session_id for flow in get_flows(client_id, artifact)}
    run_cmd(
        [
            str(VELO_BIN),
            "-a",
            str(API_CLIENT),
            "--runas",
            "api",
            "artifacts",
            "collect",
            artifact,
            "--client_id",
            client_id,
            "--org_id",
            ORG_ID,
        ],
        cwd=VELO_DIR,
    )
    deadline = time.time() + 60
    while time.time() < deadline:
        flows = get_flows(client_id, artifact)
        for flow in flows:
            if flow.session_id not in existing_ids:
                return flow.session_id
        time.sleep(2)
    raise RuntimeError(f"Timed out waiting for queued flow id for {artifact} on {client_id}")


def wait_for_flow(client_id: str, artifact: str, session_id: str, timeout_seconds: int) -> FlowRecord:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        for flow in get_flows(client_id, artifact):
            if flow.session_id == session_id:
                if flow.state not in OPEN_STATES:
                    return flow
                break
        time.sleep(5)
    raise RuntimeError(f"Timed out waiting for {session_id} ({artifact}) on {client_id}")


def fetch_results(client_id: str, artifact: str, session_id: str, output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    proc = run_cmd(
        [
            str(VELO_BIN),
            "-a",
            str(API_CLIENT),
            "--runas",
            "api",
            "query",
            "--format",
            "jsonl",
            (
                "SELECT * FROM source("
                f"client_id='{client_id}', "
                f"flow_id='{session_id}', "
                f"artifact='{artifact}')"
            ),
        ],
        cwd=VELO_DIR,
    )
    output_path.write_text(proc.stdout, encoding="utf-8")
    return sum(1 for line in proc.stdout.splitlines() if line.strip())


def write_manifest(output_dir: Path, rows: list[dict[str, str]]) -> None:
    manifest_path = output_dir / "execution-analysis-manifest.tsv"
    fieldnames = [
        "RunAtUTC",
        "Hostname",
        "ClientID",
        "Artifact",
        "SessionID",
        "State",
        "Rows",
        "ReusedFlow",
        "OutputFile",
        "LastSeen",
    ]
    with manifest_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)


def analyze_host(investigation_id: str, hostname: str, rerun: bool, timeout_seconds: int) -> None:
    client = get_client(hostname)
    output_dir = (
        REPO_ROOT
        / "investigations"
        / investigation_id
        / "evidence"
        / "systems"
        / hostname
        / "velociraptor"
        / "execution-analysis"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_rows: list[dict[str, str]] = []
    run_at = now_utc()

    for artifact in ARTIFACTS:
        flows = get_flows(client.client_id, artifact)
        reused = False
        chosen = None if rerun else pick_finished_flow(flows)
        if chosen is None:
            session_id = queue_artifact(client.client_id, artifact)
            chosen = wait_for_flow(client.client_id, artifact, session_id, timeout_seconds)
        else:
            reused = True

        slug = slugify(artifact)
        output_file = output_dir / f"{hostname}-{slug}.jsonl"
        rows = fetch_results(client.client_id, artifact, chosen.session_id, output_file)
        manifest_rows.append(
            {
                "RunAtUTC": run_at,
                "Hostname": hostname,
                "ClientID": client.client_id,
                "Artifact": artifact,
                "SessionID": chosen.session_id,
                "State": chosen.state,
                "Rows": str(rows),
                "ReusedFlow": "yes" if reused else "no",
                "OutputFile": str(output_file),
                "LastSeen": client.last_seen,
            }
        )

    write_manifest(output_dir, manifest_rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect or reuse Windows evidence-of-execution artifacts from Velociraptor."
    )
    parser.add_argument("--investigation-id", required=True, help="Case folder name under ./investigations")
    parser.add_argument("--host", action="append", required=True, help="Hostname to collect, repeat for multiple hosts")
    parser.add_argument("--rerun", action="store_true", help="Queue fresh collections instead of reusing finished flows")
    parser.add_argument("--timeout-seconds", type=int, default=900, help="Maximum wait per newly queued flow")
    return parser.parse_args()


def main() -> int:
    if not VELO_BIN.exists():
        print(f"Velociraptor binary not found at {VELO_BIN}", file=sys.stderr)
        return 1
    if not API_CLIENT.exists():
        print(f"API client config not found at {API_CLIENT}", file=sys.stderr)
        return 1

    args = parse_args()
    for host in args.host:
        analyze_host(args.investigation_id, host, args.rerun, args.timeout_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
