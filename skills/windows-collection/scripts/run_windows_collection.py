#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import grpc
import pyvelociraptor
from pyvelociraptor import api_pb2, api_pb2_grpc

REPO_ROOT = Path(__file__).resolve().parents[3]
SKILL_ROOT = Path(__file__).resolve().parents[1]
REFERENCE_DIR = SKILL_ROOT / "references"
DEFAULT_API_CLIENT = REPO_ROOT / "velociraptor" / "api_client.yaml"
DEFAULT_ORG_ID = "root"
OPEN_STATES = {"RUNNING", "IN_PROGRESS", "WAITING", "QUEUED"}
COLLECTION_TYPE_CHOICES = ("all", "execution", "persistence", "lateral-movement", "timeline")

ARTIFACT_GROUPS = {
    "triage": (
        "DetectRaptor.Windows.Detection.Evtx",
        "DetectRaptor.Windows.Detection.Applications",
        "DetectRaptor.Windows.Detection.Powershell.PSReadline",
        "DetectRaptor.Windows.Detection.MFT",
        "DetectRaptor.Windows.Detection.ZoneIdentifier",
    ),
    "execution": (
        "Windows.Detection.Amcache",
        "Windows.Forensics.Bam",
        "Windows.Forensics.RecentFileCache",
        "Windows.Forensics.Timeline",
        "Windows.Forensics.SRUM",
        "Windows.System.AppCompatPCA",
        "Windows.Forensics.Prefetch",
        "Windows.Registry.Hunter[all]",
    ),
    "persistence": (
        "Windows.Sys.StartupItems",
        "Windows.System.Services",
        "Windows.System.TaskScheduler",
        "Windows.Registry.TaskCache.HiddenTasks",
        "Windows.Registry.Hunter[all]",
        "Windows.Persistence.PermanentWMIEvents",
        "Windows.Sysinternals.Autoruns",
    ),
    "lateral-movement": (
        "Windows.Detection.PublicIP",
        "Windows.EventLogs.RDPAuth",
        "Windows.EventLogs.ExplicitLogon",
        "Windows.Registry.MountPoints2",
        "Windows.EventLogs.ServiceCreationComspec",
    ),
    "timeline": (
        "Windows.NTFS.MFT",
        "Windows.EventLogs.EvtxHunter",
    ),
    "registry": (
        "Windows.Registry.Hunter[all]",
    ),
}
ALL_COLLECTION_GROUPS = ("triage", "execution", "persistence", "lateral-movement", "registry")
REGISTRY_HUNTER_COLLECTION_LABEL = "Windows.Registry.Hunter[all]"
REGISTRY_HUNTER_SECTION_LABELS = {
    "Windows.Registry.Hunter[all]",
    "Windows.Registry.Hunter[system-info]",
    "Windows.Registry.Hunter[execution]",
}
REGISTRY_HUNTER_TIMEOUT_SECONDS = 1800

REGISTRY_HUNTER_ALL_CATEGORIES = json.dumps(
    [
        "ASEP",
        "ASEP Classes",
        "Antivirus",
        "Autoruns",
        "Cloud Storage",
        "Devices",
        "Event Logs",
        "Installed Software",
        "Microsoft Exchange",
        "Microsoft Office",
        "Network Shares",
        "Persistence",
        "Program Execution",
        "Services",
        "System Info",
        "Third Party Applications",
        "Threat Hunting",
        "User Accounts",
        "User Activity",
        "Volume Shadow Copies",
        "Web Browsers",
    ],
    separators=(",", ":"),
)
REGISTRY_HUNTER_SYSTEM_INFO_CATEGORIES = json.dumps(
    [
        "Antivirus",
        "Cloud Storage",
        "Devices",
        "Installed Software",
        "Microsoft Exchange",
        "Microsoft Office",
        "Network Shares",
        "System Info",
        "User Accounts",
        "Web Browsers",
    ],
    separators=(",", ":"),
)
REGISTRY_HUNTER_EXECUTION_CATEGORIES = json.dumps(
    ["Program Execution"],
    separators=(",", ":"),
)
MULTI_SCOPE_ARTIFACT_EXPORTS = {
    "Windows.Forensics.SRUM": (
        "Windows.Forensics.SRUM/Execution Stats",
        "Windows.Forensics.SRUM/Application Resource Usage",
        "Windows.Forensics.SRUM/Network Connections",
        "Windows.Forensics.SRUM/Network Usage",
    ),
}
CURATED_ARTIFACT_EXPORT_QUERIES = {
    "Windows.NTFS.MFT": "export_windows_ntfs_mft.vql",
    "Windows.EventLogs.EvtxHunter": "export_windows_eventlogs_evtxhunter.vql",
    "Windows.EventLogs.RDPAuth": "export_windows_eventlogs_rdpauth.vql",
    "Windows.EventLogs.ExplicitLogon": "export_windows_eventlogs_explicitlogon.vql",
}
REGISTRY_HUNTER_CURATED_PROFILES = {
    "execution": (
        (
            "Windows.Registry.Hunter.Execution.AppCompatCache.csv",
            "export_registry_hunter_execution_appcompatcache.vql",
        ),
        (
            "Windows.Registry.Hunter.Execution.UserAssist.csv",
            "export_registry_hunter_execution_userassist.vql",
        ),
        (
            "Windows.Registry.Hunter.Execution.RADAR.csv",
            "export_registry_hunter_execution_radar.vql",
        ),
        (
            "Windows.Registry.Hunter.Execution.BAM.csv",
            "export_registry_hunter_execution_bam.vql",
        ),
    ),
    "system-info": (
        (
            "Windows.Registry.Hunter.SystemInfo.csv",
            "export_registry_hunter_system_info.vql",
        ),
    ),
    "web-browsers": (
        (
            "Windows.Registry.Hunter.WebBrowsers.csv",
            "export_registry_hunter_web_browsers.vql",
        ),
    ),
    "volume-shadow-copies": (
        (
            "Windows.Registry.Hunter.VolumeShadowCopies.csv",
            "export_registry_hunter_volume_shadow_copies.vql",
        ),
    ),
    "user-activity": (
        (
            "Windows.Registry.Hunter.UserActivity.csv",
            "export_registry_hunter_user_activity.vql",
        ),
    ),
    "user-accounts": (
        (
            "Windows.Registry.Hunter.UserAccounts.csv",
            "export_registry_hunter_user_accounts.vql",
        ),
    ),
    "threat-hunting": (
        (
            "Windows.Registry.Hunter.ThreatHunting.csv",
            "export_registry_hunter_threat_hunting.vql",
        ),
    ),
    "third-party-applications": (
        (
            "Windows.Registry.Hunter.ThirdPartyApplications.csv",
            "export_registry_hunter_third_party_applications.vql",
        ),
    ),
    "services": (
        (
            "Windows.Registry.Hunter.Services.csv",
            "export_registry_hunter_services.vql",
        ),
    ),
    "network-shares": (
        (
            "Windows.Registry.Hunter.NetworkShares.csv",
            "export_registry_hunter_network_shares.vql",
        ),
    ),
    "persistence": (
        (
            "Windows.Registry.Hunter.Persistence.csv",
            "export_registry_hunter_persistence.vql",
        ),
    ),
    "program-execution": (
        (
            "Windows.Registry.Hunter.ProgramExecution.csv",
            "export_registry_hunter_program_execution.vql",
        ),
    ),
    "microsoft-office": (
        (
            "Windows.Registry.Hunter.MicrosoftOffice.csv",
            "export_registry_hunter_microsoft_office.vql",
        ),
    ),
    "microsoft-exchange": (
        (
            "Windows.Registry.Hunter.MicrosoftExchange.csv",
            "export_registry_hunter_microsoft_exchange.vql",
        ),
    ),
    "installed-software": (
        (
            "Windows.Registry.Hunter.InstalledSoftware.csv",
            "export_registry_hunter_installed_software.vql",
        ),
    ),
    "event-logs": (
        (
            "Windows.Registry.Hunter.EventLogs.csv",
            "export_registry_hunter_event_logs.vql",
        ),
    ),
    "devices": (
        (
            "Windows.Registry.Hunter.Devices.csv",
            "export_registry_hunter_devices.vql",
        ),
    ),
    "cloud-storage": (
        (
            "Windows.Registry.Hunter.CloudStorage.csv",
            "export_registry_hunter_cloud_storage.vql",
        ),
    ),
    "autoruns": (
        (
            "Windows.Registry.Hunter.Autoruns.csv",
            "export_registry_hunter_autoruns.vql",
        ),
    ),
}


@dataclass
class ClientRecord:
    client_id: str
    hostname: str
    last_seen: str


@dataclass
class ArtifactSpec:
    label: str
    artifact: str
    env: dict[str, str]
    timeout_seconds: int | None = None


@dataclass
class TimelineOptions:
    date_after: str | None = None
    date_before: str | None = None
    mft_drive: str | None = None
    mft_path_regex: str | None = None
    mft_file_regex: str | None = None
    mft_size_min: int | None = None
    mft_size_max: int | None = None
    evtx_glob: str | None = None
    evtx_ioc_regex: str | None = None
    evtx_whitelist_regex: str | None = None
    evtx_path_regex: str | None = None
    evtx_channel_regex: str | None = None
    evtx_provider_regex: str | None = None
    evtx_id_regex: str | None = None
    evtx_vss_analysis_age: int | None = None


@dataclass
class FlowRecord:
    session_id: str
    state: str
    total_rows: int
    created: str
    last_active: str
    request_timeout_seconds: int | None
    artifacts_with_results: list[str]
    requested_specs: list[ArtifactSpec]


@dataclass
class CollectionRequest:
    target_collection_type: str
    requested_groups: list[str]
    requested_artifacts: list[str]
    expected_specs: list[ArtifactSpec]


class VeloApiClient:
    def __init__(self, api_config: Path, org_id: str = DEFAULT_ORG_ID):
        self.api_config = api_config
        self.org_id = org_id
        self._channel: grpc.Channel | None = None
        self._stub: api_pb2_grpc.APIStub | None = None

    def __enter__(self) -> "VeloApiClient":
        config = pyvelociraptor.LoadConfigFile(str(self.api_config))
        creds = grpc.ssl_channel_credentials(
            root_certificates=config["ca_certificate"].encode("utf8"),
            private_key=config["client_private_key"].encode("utf8"),
            certificate_chain=config["client_cert"].encode("utf8"),
        )
        options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)
        self._channel = grpc.secure_channel(config["api_connection_string"], creds, options)
        self._stub = api_pb2_grpc.APIStub(self._channel)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._channel is not None:
            self._channel.close()
        self._channel = None
        self._stub = None

    def query(
        self,
        vql: str,
        env: dict[str, str] | None = None,
        *,
        timeout: int = 0,
        max_wait: int = 1,
        max_row: int = 1000,
    ) -> list[dict[str, Any]]:
        if self._stub is None:
            raise RuntimeError("Velociraptor API client is not connected.")

        env_items = [
            api_pb2.VQLEnv(key=key, value=value)
            for key, value in sorted((env or {}).items())
        ]
        request = api_pb2.VQLCollectorArgs(
            org_id=self.org_id,
            max_wait=max_wait,
            max_row=max_row,
            timeout=timeout,
            Query=[api_pb2.VQLRequest(Name="query", VQL=vql)],
            env=env_items,
        )

        rows: list[dict[str, Any]] = []
        for response in self._stub.Query(request):
            if response.Response:
                rows.extend(json.loads(response.Response))
        return rows

    def query_file(
        self,
        filename: str,
        env: dict[str, str] | None = None,
        *,
        timeout: int = 0,
        max_wait: int = 1,
        max_row: int = 1000,
    ) -> list[dict[str, Any]]:
        vql = (REFERENCE_DIR / filename).read_text(encoding="utf-8")
        return self.query(vql, env=env, timeout=timeout, max_wait=max_wait, max_row=max_row)


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def slugify(value: str) -> str:
    return "".join(char.lower() if char.isalnum() else "-" for char in value).strip("-").replace("--", "-")


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def short_signature(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()[:12]


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def normalize_collection_label(label: str) -> str:
    if label in REGISTRY_HUNTER_SECTION_LABELS:
        return REGISTRY_HUNTER_COLLECTION_LABEL
    return label


def normalize_artifacts(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, list):
                return [str(item) for item in parsed if str(item).strip()]
        return [item.strip() for item in text.split(",") if item.strip()]
    return []


def spec_env_from_parameters(parameters: Any) -> dict[str, str]:
    if not isinstance(parameters, dict):
        return {}
    env = parameters.get("env")
    if not isinstance(env, list):
        return {}

    env_map: dict[str, str] = {}
    for item in env:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        if not key:
            continue
        env_map[str(key)] = str(item.get("value", ""))
    return env_map


def parse_specs_json(specs_json: str) -> list[ArtifactSpec]:
    if not specs_json:
        return []
    try:
        parsed = json.loads(specs_json)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []

    specs: list[ArtifactSpec] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        artifact = item.get("artifact")
        if not artifact:
            continue
        specs.append(
            ArtifactSpec(
                label=str(item.get("artifact")),
                artifact=str(artifact),
                env=spec_env_from_parameters(item.get("parameters")),
                timeout_seconds=int(item.get("timeout") or 0) or None,
            )
        )
    return specs


def serialize_specs(specs: list[ArtifactSpec]) -> list[dict[str, Any]]:
    return [
        {
            "label": spec.label,
            "artifact": spec.artifact,
            "env": dict(sorted(spec.env.items())),
            "timeout_seconds": spec.timeout_seconds,
        }
        for spec in specs
    ]


def timeline_options_present(options: TimelineOptions | None) -> bool:
    if options is None:
        return False
    return any(
        value is not None
        for value in (
            options.date_after,
            options.date_before,
            options.mft_drive,
            options.mft_path_regex,
            options.mft_file_regex,
            options.mft_size_min,
            options.mft_size_max,
            options.evtx_glob,
            options.evtx_ioc_regex,
            options.evtx_whitelist_regex,
            options.evtx_path_regex,
            options.evtx_channel_regex,
            options.evtx_provider_regex,
            options.evtx_id_regex,
            options.evtx_vss_analysis_age,
        )
    )


def build_timeline_specs(options: TimelineOptions | None) -> list[ArtifactSpec]:
    options = options or TimelineOptions()
    if not options.date_after and not options.date_before:
        raise RuntimeError(
            "--collection-type timeline requires --date-after, --date-before, or both."
        )

    mft_env = {
        "MFTDrive": options.mft_drive or "C:",
        "PathRegex": options.mft_path_regex or ".",
        "FileRegex": options.mft_file_regex or ".",
    }
    if options.date_after:
        mft_env["DateAfter"] = options.date_after
    if options.date_before:
        mft_env["DateBefore"] = options.date_before
    if options.mft_size_min is not None:
        mft_env["SizeMin"] = str(options.mft_size_min)
    if options.mft_size_max is not None:
        mft_env["SizeMax"] = str(options.mft_size_max)

    evtx_env = {
        "EvtxGlob": options.evtx_glob or r"%SystemRoot%\System32\Winevt\Logs\*.evtx",
        "IocRegex": options.evtx_ioc_regex or ".",
        "PathRegex": options.evtx_path_regex or ".",
        "ChannelRegex": options.evtx_channel_regex or ".",
        "ProviderRegex": options.evtx_provider_regex or ".",
        "IdRegex": options.evtx_id_regex or ".",
        "VSSAnalysisAge": str(options.evtx_vss_analysis_age or 0),
    }
    if options.date_after:
        evtx_env["DateAfter"] = options.date_after
    if options.date_before:
        evtx_env["DateBefore"] = options.date_before
    if options.evtx_whitelist_regex:
        evtx_env["WhitelistRegex"] = options.evtx_whitelist_regex

    return [
        ArtifactSpec(label="Windows.NTFS.MFT", artifact="Windows.NTFS.MFT", env=mft_env),
        ArtifactSpec(
            label="Windows.EventLogs.EvtxHunter",
            artifact="Windows.EventLogs.EvtxHunter",
            env=evtx_env,
        ),
    ]


def spec_to_request_dict(spec: ArtifactSpec) -> dict[str, Any]:
    env_items = [
        {"key": key, "value": value}
        for key, value in sorted(spec.env.items())
    ]
    return {
        "artifact": spec.artifact,
        "parameters": {
            "env": env_items,
        },
    }


def normalize_specs_value(value: Any) -> list[ArtifactSpec]:
    if not isinstance(value, list):
        return []
    specs: list[ArtifactSpec] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        artifact = item.get("artifact")
        if not artifact:
            continue
        env = item.get("env")
        if not isinstance(env, dict):
            env = {}
        specs.append(
            ArtifactSpec(
                label=str(item.get("label") or artifact),
                artifact=str(artifact),
                env={str(key): str(val) for key, val in env.items()},
                timeout_seconds=int(item.get("timeout_seconds") or 0) or None,
            )
        )
    return specs


def build_plain_spec(label: str) -> ArtifactSpec:
    return ArtifactSpec(label=label, artifact=label, env={})


def build_registry_hunter_specs() -> dict[str, ArtifactSpec]:
    return {
        "Windows.Registry.Hunter[all]": ArtifactSpec(
            label="Windows.Registry.Hunter[all]",
            artifact="Windows.Registry.Hunter",
            env={
                "Categories": REGISTRY_HUNTER_ALL_CATEGORIES,
                "RemappingStrategy": "None",
            },
            timeout_seconds=REGISTRY_HUNTER_TIMEOUT_SECONDS,
        ),
        "Windows.Registry.Hunter[system-info]": ArtifactSpec(
            label="Windows.Registry.Hunter[system-info]",
            artifact="Windows.Registry.Hunter",
            env={
                "Categories": REGISTRY_HUNTER_SYSTEM_INFO_CATEGORIES,
                "RemappingStrategy": "None",
            },
            timeout_seconds=REGISTRY_HUNTER_TIMEOUT_SECONDS,
        ),
        "Windows.Registry.Hunter[execution]": ArtifactSpec(
            label="Windows.Registry.Hunter[execution]",
            artifact="Windows.Registry.Hunter",
            env={
                "Categories": REGISTRY_HUNTER_EXECUTION_CATEGORIES,
                "RemappingStrategy": "None",
            },
            timeout_seconds=REGISTRY_HUNTER_TIMEOUT_SECONDS,
        ),
    }


SPECIAL_ARTIFACT_SPECS = build_registry_hunter_specs()


def build_expected_specs(labels: list[str]) -> list[ArtifactSpec]:
    specs: list[ArtifactSpec] = []
    for label in labels:
        specs.append(SPECIAL_ARTIFACT_SPECS.get(label, build_plain_spec(label)))
    return specs


def get_mapped_client_info_path(hostname: str) -> Path:
    return REPO_ROOT / "velociraptor" / "mapped-clients" / hostname / "client-info.json"


def load_mapped_client_record(api: VeloApiClient, hostname: str) -> ClientRecord | None:
    info_path = get_mapped_client_info_path(hostname)
    if not info_path.exists():
        return None

    try:
        payload = json.loads(info_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        return None

    client_id = str(payload[0].get("client_id") or "")
    if not client_id:
        return None

    live_rows = api.query(
        """
        SELECT
          client_id,
          os_info.hostname AS Hostname,
          timestamp(epoch=last_seen_at) AS LastSeen
        FROM clients()
        WHERE client_id = ClientId
        """,
        {"ClientId": client_id},
    )
    if live_rows:
        row = live_rows[0]
        return ClientRecord(
            client_id=row["client_id"],
            hostname=row.get("Hostname") or hostname,
            last_seen=row.get("LastSeen", ""),
        )

    return ClientRecord(
        client_id=client_id,
        hostname=str(payload[0].get("Hostname") or hostname),
        last_seen=str(payload[0].get("LastSeen") or ""),
    )


def get_client(api: VeloApiClient, hostname: str) -> ClientRecord:
    rows = api.query_file("get_client.vql", {"hostname_regex": f"^{hostname}$"})
    if rows:
        row = rows[0]
        return ClientRecord(
            client_id=row["client_id"],
            hostname=row.get("Hostname") or hostname,
            last_seen=row.get("LastSeen", ""),
        )

    mapped_record = load_mapped_client_record(api, hostname)
    if mapped_record is not None:
        return mapped_record

    raise RuntimeError(f"No Velociraptor client found for hostname {hostname}")


def flow_from_row(row: dict[str, Any]) -> FlowRecord:
    requested_specs = parse_specs_json(row.get("RequestSpecsJson", ""))
    if not requested_specs:
        requested_specs = build_expected_specs(normalize_artifacts(row.get("RequestedArtifacts")))
    return FlowRecord(
        session_id=row["session_id"],
        state=(row.get("state") or "").upper(),
        total_rows=int(row.get("total_collected_rows") or 0),
        created=row.get("Created", ""),
        last_active=row.get("LastActive", ""),
        request_timeout_seconds=int(row.get("RequestTimeoutSeconds") or 0) or None,
        artifacts_with_results=normalize_artifacts(row.get("artifacts_with_results")),
        requested_specs=requested_specs,
    )


def get_all_flows(api: VeloApiClient, client_id: str) -> list[FlowRecord]:
    rows = api.query_file("list_flows.vql", {"client_id": client_id})
    return [flow_from_row(row) for row in rows]


def get_flow(api: VeloApiClient, client_id: str, flow_id: str) -> FlowRecord:
    rows = api.query_file("get_flow.vql", {"client_id": client_id, "flow_id": flow_id})
    if not rows:
        raise RuntimeError(f"Flow {flow_id} not found for client {client_id}")
    return flow_from_row(rows[0])


def get_output_dir(investigation_id: str, hostname: str) -> Path:
    return (
        REPO_ROOT
        / "investigations"
        / investigation_id
        / "evidence"
        / "systems"
        / hostname
        / "velociraptor"
        / "host-collection"
    )


def get_exports_dir(investigation_id: str, hostname: str) -> Path:
    return (
        REPO_ROOT
        / "investigations"
        / investigation_id
        / "evidence"
        / "systems"
        / hostname
        / "velociraptor"
        / "exports"
    )


def get_current_state_path(investigation_id: str, hostname: str) -> Path:
    return get_output_dir(investigation_id, hostname) / "host-collection-state.json"


def request_id_for_request(request: CollectionRequest) -> str:
    return f"{slugify(request.target_collection_type)}-{short_signature(serialize_specs(request.expected_specs))}"


def get_request_dir(investigation_id: str, hostname: str, request_id: str) -> Path:
    return get_output_dir(investigation_id, hostname) / "requests" / request_id


def get_request_state_path(investigation_id: str, hostname: str, request_id: str) -> Path:
    return get_request_dir(investigation_id, hostname, request_id) / "state.json"


def get_state_path(investigation_id: str, hostname: str, request_id: str | None = None) -> Path:
    if request_id:
        return get_request_state_path(investigation_id, hostname, request_id)
    return get_current_state_path(investigation_id, hostname)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(rendered)
        temp_name = handle.name
    os.replace(temp_name, path)


def read_state(path: Path) -> dict[str, Any]:
    raw_text = path.read_text(encoding="utf-8")
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as exc:
        decoder = json.JSONDecoder()
        payload, end = decoder.raw_decode(raw_text)
        if raw_text[end:].strip():
            return payload
        raise exc


def parse_env_assignments(env_values: list[str]) -> dict[str, str]:
    env_map: dict[str, str] = {}
    for raw_item in env_values:
        key, sep, value = raw_item.partition("=")
        key = key.strip()
        if not sep or not key:
            raise RuntimeError(f"Invalid --env value {raw_item!r}. Use KEY=VALUE.")
        env_map[key] = value
    return env_map


def build_custom_specs(extra_artifacts: list[str], artifact_env: dict[str, str]) -> dict[str, ArtifactSpec]:
    if not artifact_env:
        return {}
    if len(extra_artifacts) != 1:
        raise RuntimeError("--env requires exactly one explicit --artifact target.")

    label = normalize_collection_label(extra_artifacts[0])
    base_spec = SPECIAL_ARTIFACT_SPECS.get(label, build_plain_spec(label))
    return {
        label: ArtifactSpec(
            label=label,
            artifact=base_spec.artifact,
            env=dict(sorted(artifact_env.items())),
            timeout_seconds=base_spec.timeout_seconds,
        )
    }


def resolve_requested_groups(collection_type: str | None, extra_artifacts: list[str]) -> list[str]:
    resolved: list[str] = []
    if collection_type == "all":
        resolved.extend(ALL_COLLECTION_GROUPS)
    elif collection_type == "execution":
        resolved.append("execution")
    elif collection_type == "persistence":
        resolved.append("persistence")
    elif collection_type == "lateral-movement":
        resolved.append("lateral-movement")
    elif collection_type == "timeline":
        resolved.append("timeline")
    if not resolved and not extra_artifacts:
        resolved = list(ALL_COLLECTION_GROUPS)
    return resolved


def build_artifacts(groups: list[str], extra_artifacts: list[str]) -> list[str]:
    artifacts: list[str] = []
    for group in groups:
        artifacts.extend(ARTIFACT_GROUPS[group])
    artifacts.extend(extra_artifacts)
    return dedupe(artifacts)


def normalize_collection_artifacts(artifacts: list[str]) -> list[str]:
    return dedupe([normalize_collection_label(artifact) for artifact in artifacts])


def build_request(
    collection_type: str | None,
    extra_artifacts: list[str],
    env_values: list[str],
    timeline_options: TimelineOptions | None = None,
) -> CollectionRequest:
    if timeline_options_present(timeline_options) and collection_type != "timeline":
        raise RuntimeError("Timeline-specific flags require --collection-type timeline.")

    if collection_type == "timeline":
        if extra_artifacts:
            raise RuntimeError("--collection-type timeline cannot be combined with --artifact.")
        if env_values:
            raise RuntimeError("--collection-type timeline does not use --env. Use the dedicated timeline flags.")
        expected_specs = build_timeline_specs(timeline_options)
        requested_groups = ["timeline"]
        requested_artifacts = [spec.label for spec in expected_specs]
        return CollectionRequest(
            target_collection_type="timeline",
            requested_groups=requested_groups,
            requested_artifacts=requested_artifacts,
            expected_specs=expected_specs,
        )

    requested_groups = resolve_requested_groups(collection_type, extra_artifacts)
    requested_artifacts = normalize_collection_artifacts(build_artifacts(requested_groups, extra_artifacts))
    if not requested_artifacts:
        raise RuntimeError("No artifacts resolved for the requested collection target.")
    custom_specs = build_custom_specs(extra_artifacts, parse_env_assignments(env_values))
    expected_specs = [
        custom_specs.get(label, SPECIAL_ARTIFACT_SPECS.get(label, build_plain_spec(label)))
        for label in requested_artifacts
    ]
    if collection_type:
        target_collection_type = collection_type
    elif requested_groups == list(ALL_COLLECTION_GROUPS) and not extra_artifacts:
        target_collection_type = "all"
    elif len(requested_artifacts) == 1:
        target_collection_type = requested_artifacts[0]
    elif extra_artifacts:
        target_collection_type = "artifacts"
    else:
        target_collection_type = "+".join(requested_groups)
    return CollectionRequest(
        target_collection_type=target_collection_type,
        requested_groups=requested_groups,
        requested_artifacts=requested_artifacts,
        expected_specs=expected_specs,
    )


def timeline_options_from_args(args: argparse.Namespace) -> TimelineOptions:
    return TimelineOptions(
        date_after=getattr(args, "date_after", None),
        date_before=getattr(args, "date_before", None),
        mft_drive=getattr(args, "mft_drive", None),
        mft_path_regex=getattr(args, "mft_path_regex", None),
        mft_file_regex=getattr(args, "mft_file_regex", None),
        mft_size_min=getattr(args, "mft_size_min", None),
        mft_size_max=getattr(args, "mft_size_max", None),
        evtx_glob=getattr(args, "evtx_glob", None),
        evtx_ioc_regex=getattr(args, "evtx_ioc_regex", None),
        evtx_whitelist_regex=getattr(args, "evtx_whitelist_regex", None),
        evtx_path_regex=getattr(args, "evtx_path_regex", None),
        evtx_channel_regex=getattr(args, "evtx_channel_regex", None),
        evtx_provider_regex=getattr(args, "evtx_provider_regex", None),
        evtx_id_regex=getattr(args, "evtx_id_regex", None),
        evtx_vss_analysis_age=getattr(args, "evtx_vss_analysis_age", None),
    )


def build_request_from_args(args: argparse.Namespace) -> CollectionRequest:
    return build_request(
        args.collection_type,
        args.artifact or [],
        args.env or [],
        timeline_options_from_args(args),
    )


def spec_matches_expected(actual: ArtifactSpec, expected: ArtifactSpec) -> bool:
    if actual.artifact != expected.artifact:
        return False
    for key, expected_value in expected.env.items():
        if actual.env.get(key) != expected_value:
            return False
    return True


def flow_matches_spec(flow: FlowRecord, expected: ArtifactSpec) -> bool:
    if expected.timeout_seconds is not None and flow.request_timeout_seconds != expected.timeout_seconds:
        return False
    return any(spec_matches_expected(actual_spec, expected) for actual_spec in flow.requested_specs)


def find_matching_flow_for_spec(api: VeloApiClient, client_id: str, expected: ArtifactSpec) -> FlowRecord | None:
    for flow in get_all_flows(api, client_id):
        if flow_matches_spec(flow, expected):
            return flow
    return None


def flow_is_finished(flow: FlowRecord) -> bool:
    return flow.state not in OPEN_STATES


def result_components_for_artifact(artifact: str, flow: FlowRecord) -> list[str]:
    return [
        component
        for component in flow.artifacts_with_results
        if component == artifact or component.startswith(f"{artifact}/")
    ]


def query_artifact_source(api: VeloApiClient, client_id: str, flow_id: str, artifact: str) -> list[dict[str, Any]]:
    env = {
        "ClientId": client_id,
        "FlowId": flow_id,
        "ArtifactName": artifact,
    }
    last_error: grpc.RpcError | None = None
    for max_row in (1000, 250, 100, 50, 10, 1):
        try:
            return api.query_file(
                "export_source.vql",
                env,
                timeout=0,
                max_wait=30,
                max_row=max_row,
            )
        except grpc.RpcError as exc:
            if exc.code() != grpc.StatusCode.RESOURCE_EXHAUSTED:
                raise
            last_error = exc
    if last_error is not None:
        raise last_error
    return []


def query_registry_hunter_categories(api: VeloApiClient, client_id: str, flow_id: str) -> list[str]:
    rows = api.query_file(
        "export_registry_hunter_categories.vql",
        {
            "ClientId": client_id,
            "FlowId": flow_id,
        },
        timeout=0,
        max_wait=30,
        max_row=1000,
    )
    return [str(row.get("Category")) for row in rows if str(row.get("Category") or "").strip()]


def query_registry_hunter_category_rows(
    api: VeloApiClient,
    client_id: str,
    flow_id: str,
    category: str,
) -> list[dict[str, Any]]:
    return api.query_file(
        "export_registry_hunter_category.vql",
        {
            "ClientId": client_id,
            "FlowId": flow_id,
            "RequestedCategory": category,
        },
        timeout=0,
        max_wait=30,
        max_row=1000,
    )


def query_curated_artifact_rows(
    api: VeloApiClient,
    artifact_name: str,
    client_id: str,
    flow_id: str,
) -> list[dict[str, Any]]:
    query_filename = CURATED_ARTIFACT_EXPORT_QUERIES[artifact_name]
    last_error: grpc.RpcError | None = None
    for max_row in (1000, 250, 100, 50, 10, 1):
        try:
            return api.query_file(
                query_filename,
                {
                    "ClientId": client_id,
                    "FlowId": flow_id,
                },
                timeout=0,
                max_wait=30,
                max_row=max_row,
            )
        except grpc.RpcError as exc:
            if exc.code() != grpc.StatusCode.RESOURCE_EXHAUSTED:
                raise
            last_error = exc
    if last_error is not None:
        raise last_error
    return []


def format_csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)
    return str(value)


def csv_headers(rows: list[dict[str, Any]]) -> list[str]:
    headers: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key in seen:
                continue
            seen.add(key)
            headers.append(key)
    return headers


def write_csv(path: Path, rows: list[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = csv_headers(rows)
    with path.open("w", encoding="utf-8", newline="") as handle:
        if not headers:
            return 0
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow({header: format_csv_value(row.get(header)) for header in headers})
    return len(rows)


def spec_signature(spec: ArtifactSpec) -> str:
    return short_signature(
        {
            "label": spec.label,
            "artifact": spec.artifact,
            "env": dict(sorted(spec.env.items())),
            "timeout_seconds": spec.timeout_seconds,
        }
    )


def spec_output_suffix(spec: ArtifactSpec) -> str:
    if not spec.env and spec.timeout_seconds is None:
        return ""
    date_after = spec.env.get("DateAfter")
    date_before = spec.env.get("DateBefore")
    parts = [slugify(part) for part in (date_after, date_before) if part]
    parts.append(spec_signature(spec))
    return "-".join(parts)


def request_output_suffix(request: CollectionRequest) -> str:
    if not any(spec.env or spec.timeout_seconds is not None for spec in request.expected_specs):
        return ""
    parts: list[str] = []
    if request.target_collection_type == "timeline":
        parts.append("timeline")
        sample_spec = request.expected_specs[0]
        for key in ("DateAfter", "DateBefore"):
            value = sample_spec.env.get(key)
            if value:
                parts.append(slugify(value))
    parts.append(short_signature(serialize_specs(request.expected_specs)))
    return "-".join(parts)


def append_suffix(filename: str, suffix: str) -> str:
    if not suffix:
        return filename
    stem, dot, ext = filename.rpartition(".")
    if not dot:
        return f"{filename}_{suffix}"
    return f"{stem}_{suffix}.{ext}"


def export_filename_for_artifact(label: str, suffix: str = "") -> str:
    return append_suffix(f"{label}_full.csv", suffix)


def export_filename_for_component(component: str, suffix: str = "") -> str:
    return append_suffix(f"{component.replace('/', '.')}.csv", suffix)


def export_filename_for_registry_category(category: str, suffix: str = "") -> str:
    return append_suffix(f"Windows.Registry.Hunter.{slugify(category)}.csv", suffix)


def export_generic_artifact(
    api: VeloApiClient,
    client_id: str,
    exports_dir: Path,
    artifact_status: dict[str, Any],
    filename_suffix: str,
) -> dict[str, Any]:
    components = list(artifact_status.get("available_result_components") or [])
    if not components and int(artifact_status.get("total_rows") or 0) == 0:
        output_path = exports_dir / export_filename_for_artifact(str(artifact_status["artifact"]), filename_suffix)
        row_count = write_csv(output_path, [])
        return {
            "artifact": artifact_status["artifact"],
            "flow_id": artifact_status["flow_id"],
            "mode": "full",
            "source_components": [],
            "row_count": row_count,
            "output_file": str(output_path),
        }
    if not components:
        components = [str(artifact_status["artifact_name"])]

    rows: list[dict[str, Any]] = []
    for component in components:
        component_rows = query_artifact_source(
            api,
            client_id,
            str(artifact_status["flow_id"]),
            component,
        )
        if len(components) > 1:
            component_rows = [
                {
                    "ExportComponent": component,
                    **row,
                }
                for row in component_rows
            ]
        rows.extend(component_rows)

    output_path = exports_dir / export_filename_for_artifact(str(artifact_status["artifact"]), filename_suffix)
    row_count = write_csv(output_path, rows)
    return {
        "artifact": artifact_status["artifact"],
        "flow_id": artifact_status["flow_id"],
        "mode": "full",
        "source_components": components,
        "row_count": row_count,
        "output_file": str(output_path),
    }


def export_curated_artifact(
    api: VeloApiClient,
    client_id: str,
    exports_dir: Path,
    artifact_status: dict[str, Any],
    filename_suffix: str,
) -> dict[str, Any]:
    artifact_name = str(artifact_status["artifact_name"])
    rows = query_curated_artifact_rows(
        api,
        artifact_name,
        client_id,
        str(artifact_status["flow_id"]),
    )
    output_path = exports_dir / export_filename_for_artifact(str(artifact_status["artifact"]), filename_suffix)
    row_count = write_csv(output_path, rows)
    return {
        "artifact": artifact_status["artifact"],
        "flow_id": artifact_status["flow_id"],
        "mode": "curated",
        "query_file": str(REFERENCE_DIR / CURATED_ARTIFACT_EXPORT_QUERIES[artifact_name]),
        "source_components": [artifact_name],
        "row_count": row_count,
        "output_file": str(output_path),
    }


def export_multi_scope_artifact(
    api: VeloApiClient,
    client_id: str,
    exports_dir: Path,
    artifact_status: dict[str, Any],
    filename_suffix: str,
) -> list[dict[str, Any]]:
    exports: list[dict[str, Any]] = []
    for component in MULTI_SCOPE_ARTIFACT_EXPORTS[str(artifact_status["artifact_name"])]:
        rows = query_artifact_source(
            api,
            client_id,
            str(artifact_status["flow_id"]),
            component,
        )
        output_path = exports_dir / export_filename_for_component(component, filename_suffix)
        row_count = write_csv(output_path, rows)
        exports.append(
            {
                "artifact": artifact_status["artifact"],
                "flow_id": artifact_status["flow_id"],
                "mode": "component",
                "source_components": [component],
                "row_count": row_count,
                "output_file": str(output_path),
            }
        )
    return exports


def export_registry_hunter(
    api: VeloApiClient,
    client_id: str,
    exports_dir: Path,
    artifact_status: dict[str, Any],
    filename_suffix: str,
) -> list[dict[str, Any]]:
    results_component = "Windows.Registry.Hunter/Results"
    exports: list[dict[str, Any]] = []
    for category in sorted(query_registry_hunter_categories(api, client_id, str(artifact_status["flow_id"]))):
        rows = query_registry_hunter_category_rows(
            api,
            client_id,
            str(artifact_status["flow_id"]),
            category,
        )
        output_path = exports_dir / export_filename_for_registry_category(category, filename_suffix)
        row_count = write_csv(output_path, rows)
        exports.append(
            {
                "artifact": artifact_status["artifact"],
                "flow_id": artifact_status["flow_id"],
                "mode": "registry-category",
                "category": category,
                "source_components": [results_component],
                "row_count": row_count,
                "output_file": str(output_path),
            }
        )
    return exports


def resolve_export_request(args: argparse.Namespace, investigation_id: str, hostname: str) -> CollectionRequest:
    if getattr(args, "request_id", None) and (
        args.collection_type or args.artifact or args.env or timeline_options_present(timeline_options_from_args(args))
    ):
        raise RuntimeError("--request-id cannot be combined with explicit export target arguments.")
    if args.collection_type or args.artifact or args.env:
        return build_request_from_args(args)

    state_path = get_state_path(investigation_id, hostname, getattr(args, "request_id", None))
    if not state_path.exists():
        raise RuntimeError(
            "No export target was supplied and no saved state file exists. "
            "Pass --collection-type, --artifact, or queue a collection first."
        )
    state = read_state(state_path)
    return request_from_state(state, normalize_artifacts(state.get("requested_artifacts")))


def export_collection(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    request: CollectionRequest,
) -> dict[str, Any]:
    client, artifact_statuses = get_matching_artifact_statuses(api, hostname, request)
    ensure_exportable_artifacts(artifact_statuses)

    exports_dir = get_exports_dir(investigation_id, hostname)
    exports_dir.mkdir(parents=True, exist_ok=True)
    filename_suffix = request_output_suffix(request)

    exported_files: list[dict[str, Any]] = []
    for artifact_status in artifact_statuses:
        if str(artifact_status["artifact_name"]) == "Windows.Registry.Hunter":
            exported_files.extend(
                export_registry_hunter(api, client.client_id, exports_dir, artifact_status, filename_suffix)
            )
        elif str(artifact_status["artifact_name"]) in CURATED_ARTIFACT_EXPORT_QUERIES:
            exported_files.append(
                export_curated_artifact(api, client.client_id, exports_dir, artifact_status, filename_suffix)
            )
        elif str(artifact_status["artifact_name"]) in MULTI_SCOPE_ARTIFACT_EXPORTS:
            exported_files.extend(
                export_multi_scope_artifact(api, client.client_id, exports_dir, artifact_status, filename_suffix)
            )
        else:
            exported_files.append(
                export_generic_artifact(api, client.client_id, exports_dir, artifact_status, filename_suffix)
            )

    manifest = {
        "exported_at": now_utc(),
        "investigation_id": investigation_id,
        "hostname": hostname,
        "client_id": client.client_id,
        "request_id": request_id_for_request(request),
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "exported_files": exported_files,
    }
    manifest_name = f"windows-collection-export-{slugify(request.target_collection_type)}.json"
    manifest_path = exports_dir / append_suffix(manifest_name, filename_suffix)
    write_json(manifest_path, manifest)
    manifest["manifest_file"] = str(manifest_path)
    return manifest


def get_matching_artifact_statuses(
    api: VeloApiClient,
    hostname: str,
    request: CollectionRequest,
) -> tuple[ClientRecord, list[dict[str, Any]]]:
    client = get_client(api, hostname)
    artifact_statuses = [
        artifact_status_from_flow(expected, find_matching_flow_for_spec(api, client.client_id, expected))
        for expected in request.expected_specs
    ]
    return client, artifact_statuses


def ensure_exportable_artifacts(artifact_statuses: list[dict[str, Any]]) -> None:
    incomplete = [
        item["artifact"]
        for item in artifact_statuses
        if not item["matching_flow_found"] or not item["is_finished"]
    ]
    if incomplete:
        raise RuntimeError(
            "Cannot export incomplete collection target. Missing or unfinished artifacts: "
            + ", ".join(incomplete)
        )


def export_registry_hunter_curated_profile(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    profile: str,
) -> dict[str, Any]:
    if profile not in REGISTRY_HUNTER_CURATED_PROFILES:
        raise RuntimeError(
            f"Unsupported Registry Hunter profile {profile!r}. "
            f"Supported profiles: {', '.join(sorted(REGISTRY_HUNTER_CURATED_PROFILES))}"
        )

    request = build_request(None, [REGISTRY_HUNTER_COLLECTION_LABEL], [])
    client, artifact_statuses = get_matching_artifact_statuses(api, hostname, request)
    ensure_exportable_artifacts(artifact_statuses)
    registry_status = artifact_statuses[0]

    exports_dir = get_exports_dir(investigation_id, hostname)
    exports_dir.mkdir(parents=True, exist_ok=True)

    exported_files: list[dict[str, Any]] = []
    for output_name, query_filename in REGISTRY_HUNTER_CURATED_PROFILES[profile]:
        rows = api.query_file(
            query_filename,
            {
                "ClientId": client.client_id,
                "FlowId": str(registry_status["flow_id"]),
            },
            timeout=0,
            max_wait=30,
            max_row=500,
        )
        output_path = exports_dir / output_name
        row_count = write_csv(output_path, rows)
        exported_files.append(
            {
                "artifact": registry_status["artifact"],
                "flow_id": registry_status["flow_id"],
                "mode": "registry-curated",
                "profile": profile,
                "query_file": str(REFERENCE_DIR / query_filename),
                "row_count": row_count,
                "output_file": str(output_path),
            }
        )

    manifest = {
        "exported_at": now_utc(),
        "investigation_id": investigation_id,
        "hostname": hostname,
        "client_id": client.client_id,
        "request_id": request_id_for_request(request),
        "target_collection_type": REGISTRY_HUNTER_COLLECTION_LABEL,
        "profile": profile,
        "requested_artifacts": [REGISTRY_HUNTER_COLLECTION_LABEL],
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "exported_files": exported_files,
    }
    manifest_path = exports_dir / f"windows-collection-export-registry-hunter-{slugify(profile)}.json"
    write_json(manifest_path, manifest)
    manifest["manifest_file"] = str(manifest_path)
    return manifest


def artifact_status_from_flow(expected: ArtifactSpec, flow: FlowRecord | None, queue_response_file: str = "") -> dict[str, Any]:
    if flow is None:
        return {
            "artifact": expected.label,
            "artifact_name": expected.artifact,
            "expected_env": dict(sorted(expected.env.items())),
            "expected_timeout_seconds": expected.timeout_seconds,
            "matching_flow_found": False,
            "matching_flow_matches_expected_arguments": False,
            "flow_id": "",
            "flow_state": "MISSING",
            "created": "",
            "last_active": "",
            "matched_flow_request_timeout_seconds": None,
            "total_rows": 0,
            "matched_flow_requested_specs": [],
            "available_result_components": [],
            "is_finished": False,
            "is_expected_complete": False,
            "queue_response_file": queue_response_file,
        }

    return {
        "artifact": expected.label,
        "artifact_name": expected.artifact,
        "expected_env": dict(sorted(expected.env.items())),
        "expected_timeout_seconds": expected.timeout_seconds,
        "matching_flow_found": True,
        "matching_flow_matches_expected_arguments": flow_matches_spec(flow, expected),
        "flow_id": flow.session_id,
        "flow_state": flow.state,
        "created": flow.created,
        "last_active": flow.last_active,
        "matched_flow_request_timeout_seconds": flow.request_timeout_seconds,
        "total_rows": flow.total_rows,
        "matched_flow_requested_specs": serialize_specs(flow.requested_specs),
        "available_result_components": result_components_for_artifact(expected.artifact, flow),
        "is_finished": flow_is_finished(flow),
        "is_expected_complete": flow_is_finished(flow),
        "queue_response_file": queue_response_file,
    }


def summarize_artifact_statuses(artifact_statuses: list[dict[str, Any]]) -> dict[str, Any]:
    artifacts_missing = [item["artifact"] for item in artifact_statuses if not item["matching_flow_found"]]
    artifacts_in_progress = [
        item["artifact"] for item in artifact_statuses if item["matching_flow_found"] and not item["is_finished"]
    ]
    artifacts_finished = [item["artifact"] for item in artifact_statuses if item["is_finished"]]
    artifacts_with_results = [
        item["artifact"] for item in artifact_statuses if item["available_result_components"]
    ]
    artifacts_expected_no_results = [
        item["artifact"] for item in artifact_statuses if item["is_finished"] and not item["available_result_components"]
    ]

    return {
        "all_artifacts_have_matching_flow": not artifacts_missing,
        "all_artifacts_expected_complete": all(item["is_expected_complete"] for item in artifact_statuses),
        "artifacts_missing": artifacts_missing,
        "artifacts_in_progress": artifacts_in_progress,
        "artifacts_finished": artifacts_finished,
        "artifacts_with_results": artifacts_with_results,
        "artifacts_expected_no_results": artifacts_expected_no_results,
    }


def build_state_payload(
    client: ClientRecord,
    investigation_id: str,
    hostname: str,
    request: CollectionRequest,
    artifact_statuses: list[dict[str, Any]],
) -> dict[str, Any]:
    artifact_flows: dict[str, Any] = {}
    for item in artifact_statuses:
        artifact_flows[item["artifact"]] = {
            "flow_id": item["flow_id"],
            "queue_response_file": item["queue_response_file"],
            "matched_flow_requested_specs": item["matched_flow_requested_specs"],
            "artifact_name": item["artifact_name"],
            "expected_env": item["expected_env"],
            "expected_timeout_seconds": item["expected_timeout_seconds"],
            "matched_flow_request_timeout_seconds": item["matched_flow_request_timeout_seconds"],
        }

    return {
        "queued_at": now_utc(),
        "updated_at": now_utc(),
        "investigation_id": investigation_id,
        "hostname": hostname,
        "client_id": client.client_id,
        "last_seen": client.last_seen,
        "request_id": request_id_for_request(request),
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "artifact_flows": artifact_flows,
    }


def write_state(investigation_id: str, hostname: str, payload: dict[str, Any]) -> None:
    request_id = str(payload.get("request_id", "")).strip()
    if not request_id:
        request = request_from_state(payload, normalize_artifacts(payload.get("requested_artifacts")))
        request_id = request_id_for_request(request)
    request_state_path = get_request_state_path(investigation_id, hostname, request_id)
    payload["request_id"] = request_id
    payload["state_file"] = str(request_state_path)
    payload["current_state_file"] = str(get_current_state_path(investigation_id, hostname))
    persisted_payload = dict(payload)
    write_json(request_state_path, persisted_payload)
    write_json(get_current_state_path(investigation_id, hostname), persisted_payload)


def queue_single_artifact(
    api: VeloApiClient,
    client: ClientRecord,
    investigation_id: str,
    hostname: str,
    expected: ArtifactSpec,
    timeout_seconds: int,
) -> dict[str, Any]:
    output_dir = get_output_dir(investigation_id, hostname)
    output_dir.mkdir(parents=True, exist_ok=True)

    before_ids = {flow.session_id for flow in get_all_flows(api, client.client_id)}
    rows = api.query_file(
        "queue_collect_client.vql",
        {
            "ClientId": client.client_id,
            "Artifacts": json.dumps([expected.artifact]),
            "Spec": json.dumps(spec_to_request_dict(expected), separators=(",", ":")),
            "FlowTimeoutSeconds": str(expected.timeout_seconds or 0),
        },
        timeout=timeout_seconds,
    )
    queue_suffix = spec_output_suffix(expected)
    queue_basename = f"{hostname}-{slugify(expected.label)}-queue.json"
    queue_response_path = output_dir / append_suffix(queue_basename, queue_suffix)
    write_json(queue_response_path, rows)

    flow_id = ""
    if rows:
        flow_id = str(rows[0].get("flow_id", ""))

    deadline = time.time() + timeout_seconds
    flow: FlowRecord | None = None
    while time.time() < deadline:
        if flow_id:
            try:
                flow = get_flow(api, client.client_id, flow_id)
            except RuntimeError:
                flow = None
        else:
            for candidate in get_all_flows(api, client.client_id):
                if candidate.session_id in before_ids:
                    continue
                if flow_matches_spec(candidate, expected):
                    flow = candidate
                    break
        if flow is not None:
            break
        time.sleep(2)

    if flow is None:
        raise RuntimeError(f"Timed out waiting for queued flow id for {expected.label} on {hostname}")

    return artifact_status_from_flow(expected, flow, str(queue_response_path))


def legacy_artifact_flow_map(state: dict[str, Any], request: CollectionRequest) -> dict[str, Any]:
    artifact_flows = state.get("artifact_flows")
    if isinstance(artifact_flows, dict):
        return artifact_flows

    flow_id = state.get("flow_id")
    if not flow_id:
        return {}

    collect_stdout_file = str(state.get("collect_stdout_file", ""))
    return {
        artifact: {
            "flow_id": flow_id,
            "queue_response_file": collect_stdout_file,
            "matched_flow_requested_specs": state.get("matched_flow_requested_specs", []),
        }
        for artifact in request.requested_artifacts
    }


def request_from_state(state: dict[str, Any], fallback_artifacts: list[str]) -> CollectionRequest:
    requested_groups = normalize_artifacts(state.get("requested_groups"))
    requested_artifacts = normalize_artifacts(state.get("requested_artifacts")) or fallback_artifacts
    expected_specs = normalize_specs_value(state.get("expected_spec_arguments")) or build_expected_specs(requested_artifacts)
    target_collection_type = str(state.get("target_collection_type", "")) or "+".join(requested_groups)
    return CollectionRequest(
        target_collection_type=target_collection_type,
        requested_groups=requested_groups,
        requested_artifacts=requested_artifacts,
        expected_specs=expected_specs,
    )


def check_collection(api: VeloApiClient, investigation_id: str, hostname: str, request: CollectionRequest) -> dict[str, Any]:
    client = get_client(api, hostname)
    artifact_statuses = [
        artifact_status_from_flow(expected, find_matching_flow_for_spec(api, client.client_id, expected))
        for expected in request.expected_specs
    ]

    return {
        "investigation_id": investigation_id,
        "hostname": hostname,
        "client_id": client.client_id,
        "last_seen": client.last_seen,
        "request_id": request_id_for_request(request),
        "state_file": str(get_request_state_path(investigation_id, hostname, request_id_for_request(request))),
        "current_state_file": str(get_current_state_path(investigation_id, hostname)),
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "artifact_flows": artifact_statuses,
        **summarize_artifact_statuses(artifact_statuses),
    }


def queue_collection(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    request: CollectionRequest,
    timeout_seconds: int,
) -> dict[str, Any]:
    client = get_client(api, hostname)
    artifact_statuses = [
        queue_single_artifact(api, client, investigation_id, hostname, expected, timeout_seconds)
        for expected in request.expected_specs
    ]
    state = build_state_payload(client, investigation_id, hostname, request, artifact_statuses)
    write_state(investigation_id, hostname, state)
    return {
        "action": "queued_new_flows",
        "investigation_id": investigation_id,
        "hostname": hostname,
        "client_id": client.client_id,
        "last_seen": client.last_seen,
        "request_id": request_id_for_request(request),
        "state_file": state["state_file"],
        "current_state_file": state["current_state_file"],
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "artifact_flows": artifact_statuses,
        **summarize_artifact_statuses(artifact_statuses),
    }


def status_payload(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    request_id: str | None = None,
) -> dict[str, Any]:
    state_path = get_state_path(investigation_id, hostname, request_id)
    if not state_path.exists():
        raise RuntimeError(f"No saved state file found at {state_path}")

    state = read_state(state_path)
    request = request_from_state(state, normalize_artifacts(state.get("requested_artifacts")))
    client = get_client(api, hostname)
    artifact_flow_map = legacy_artifact_flow_map(state, request)

    artifact_statuses: list[dict[str, Any]] = []
    for expected in request.expected_specs:
        stored = artifact_flow_map.get(expected.label, {})
        if not stored and expected.label != expected.artifact:
            stored = artifact_flow_map.get(expected.artifact, {})
        flow_id = str(stored.get("flow_id", ""))
        if not flow_id:
            artifact_statuses.append(artifact_status_from_flow(expected, None, str(stored.get("queue_response_file", ""))))
            continue
        flow = get_flow(api, client.client_id, flow_id)
        artifact_statuses.append(artifact_status_from_flow(expected, flow, str(stored.get("queue_response_file", ""))))

    refreshed_state = build_state_payload(client, investigation_id, hostname, request, artifact_statuses)
    write_state(investigation_id, hostname, refreshed_state)

    return {
        "investigation_id": investigation_id,
        "hostname": hostname,
        "client_id": client.client_id,
        "last_seen": client.last_seen,
        "request_id": refreshed_state["request_id"],
        "state_file": refreshed_state["state_file"],
        "current_state_file": refreshed_state["current_state_file"],
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "artifact_flows": artifact_statuses,
        **summarize_artifact_statuses(artifact_statuses),
    }


def poll_collection(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    interval_seconds: int,
    timeout_seconds: int,
    request_id: str | None = None,
) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    latest = status_payload(api, investigation_id, hostname, request_id=request_id)
    while not latest["all_artifacts_expected_complete"]:
        if time.time() >= deadline:
            latest["poll_timed_out"] = True
            latest["poll_interval_seconds"] = interval_seconds
            latest["poll_timeout_seconds"] = timeout_seconds
            return latest
        time.sleep(interval_seconds)
        latest = status_payload(api, investigation_id, hostname, request_id=request_id)

    latest["poll_timed_out"] = False
    latest["poll_interval_seconds"] = interval_seconds
    latest["poll_timeout_seconds"] = timeout_seconds
    return latest


def maybe_poll_after_collection(
    api: VeloApiClient,
    payload: dict[str, Any],
    investigation_id: str,
    hostname: str,
    poll_after: bool,
    poll_interval_seconds: int,
    poll_timeout_seconds: int,
) -> dict[str, Any]:
    if not poll_after:
        payload["polled_after_action"] = False
        return payload

    latest = poll_collection(
        api,
        investigation_id,
        hostname,
        poll_interval_seconds,
        poll_timeout_seconds,
        request_id=payload.get("request_id"),
    )
    latest["action"] = payload.get("action", "")
    latest["polled_after_action"] = True
    return latest


def maybe_export_after_collection(
    api: VeloApiClient,
    payload: dict[str, Any],
    investigation_id: str,
    hostname: str,
    request: CollectionRequest,
    export_after: bool,
) -> dict[str, Any]:
    if not export_after:
        payload["exported_after_action"] = False
        payload["export_skipped_reason"] = "disabled"
        return payload

    if not payload.get("all_artifacts_expected_complete"):
        payload["exported_after_action"] = False
        payload["export_skipped_reason"] = "collection_incomplete"
        return payload

    manifest = export_collection(api, investigation_id, hostname, request)
    payload["exported_after_action"] = True
    payload["export_manifest_file"] = manifest["manifest_file"]
    payload["exported_files"] = manifest["exported_files"]
    return payload


def ensure_collection(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    request: CollectionRequest,
    timeout_seconds: int,
    force_run: bool,
) -> dict[str, Any]:
    client = get_client(api, hostname)
    existing_artifact_flow_map: dict[str, Any] = {}
    state_path = get_current_state_path(investigation_id, hostname)
    if state_path.exists():
        existing_state = read_state(state_path)
        existing_request = request_from_state(existing_state, request.requested_artifacts)
        existing_artifact_flow_map = legacy_artifact_flow_map(existing_state, existing_request)
    artifact_statuses: list[dict[str, Any]] = []
    queued_any = False
    reused_any = False

    for expected in request.expected_specs:
        matching_flow = None if force_run else find_matching_flow_for_spec(api, client.client_id, expected)
        if matching_flow is None:
            artifact_statuses.append(
                queue_single_artifact(api, client, investigation_id, hostname, expected, timeout_seconds)
            )
            queued_any = True
        else:
            stored = existing_artifact_flow_map.get(expected.label, {})
            if not stored and expected.label != expected.artifact:
                stored = existing_artifact_flow_map.get(expected.artifact, {})
            artifact_statuses.append(
                artifact_status_from_flow(expected, matching_flow, str(stored.get("queue_response_file", "")))
            )
            reused_any = True

    state = build_state_payload(client, investigation_id, hostname, request, artifact_statuses)
    write_state(investigation_id, hostname, state)

    if force_run:
        action = "forced_new_flows"
    elif queued_any and reused_any:
        action = "reused_and_queued_flows"
    elif queued_any:
        action = "queued_new_flows"
    else:
        action = "reused_existing_flows"

    return {
        "action": action,
        "investigation_id": investigation_id,
        "hostname": hostname,
        "client_id": client.client_id,
        "last_seen": client.last_seen,
        "request_id": request_id_for_request(request),
        "state_file": state["state_file"],
        "current_state_file": state["current_state_file"],
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "artifact_flows": artifact_statuses,
        **summarize_artifact_statuses(artifact_statuses),
    }


def add_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--collection-type",
        choices=COLLECTION_TYPE_CHOICES,
        help=(
            "Named target collection type. Use all for the full baseline set, "
            "execution for the focused subset, persistence for the "
            "persistence-focused subset, lateral-movement for the remote "
            "access and auth-focused subset, or timeline for bounded MFT+EVTX "
            "pivots."
        ),
    )
    parser.add_argument("--artifact", action="append", default=[], help="Extra artifact to include")
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        help="Artifact variable in KEY=VALUE form. Repeat to pass multiple values. Requires exactly one --artifact.",
    )


def add_request_id_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--request-id",
        help=(
            "Saved request id under velociraptor/host-collection/requests/<request-id>/. "
            "Use this to inspect or export a specific prior collection state instead of the latest one."
        ),
    )


def add_timeline_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--date-after",
        help="Timeline lower bound in UTC, for example 2026-05-01T00:00:00Z. Used only with --collection-type timeline.",
    )
    parser.add_argument(
        "--date-before",
        help="Timeline upper bound in UTC, for example 2026-05-01T06:00:00Z. Used only with --collection-type timeline.",
    )
    parser.add_argument(
        "--mft-drive",
        help="Drive or pathspec to query with Windows.NTFS.MFT. Defaults to C: for timeline pivots.",
    )
    parser.add_argument(
        "--mft-path-regex",
        help="Optional OSPath regex for Windows.NTFS.MFT timeline pivots. Defaults to .",
    )
    parser.add_argument(
        "--mft-file-regex",
        help="Optional filename regex for Windows.NTFS.MFT timeline pivots. Defaults to .",
    )
    parser.add_argument(
        "--mft-size-min",
        type=int,
        help="Optional minimum file size in bytes for Windows.NTFS.MFT timeline pivots.",
    )
    parser.add_argument(
        "--mft-size-max",
        type=int,
        help="Optional maximum file size in bytes for Windows.NTFS.MFT timeline pivots.",
    )
    parser.add_argument(
        "--evtx-glob",
        help=r"Optional EVTX glob for Windows.EventLogs.EvtxHunter. Defaults to %%SystemRoot%%\System32\Winevt\Logs\*.evtx.",
    )
    parser.add_argument(
        "--evtx-ioc-regex",
        help="Optional message/EventData regex for Windows.EventLogs.EvtxHunter. Defaults to . for bounded broad review.",
    )
    parser.add_argument(
        "--evtx-whitelist-regex",
        help="Optional whitelist regex to suppress known-benign EVTX hits.",
    )
    parser.add_argument(
        "--evtx-path-regex",
        help="Optional EVTX path regex. Defaults to .",
    )
    parser.add_argument(
        "--evtx-channel-regex",
        help="Optional EVTX channel regex. Defaults to .",
    )
    parser.add_argument(
        "--evtx-provider-regex",
        help="Optional EVTX provider regex. Defaults to .",
    )
    parser.add_argument(
        "--evtx-id-regex",
        help="Optional EVTX event id regex. Defaults to .",
    )
    parser.add_argument(
        "--evtx-vss-analysis-age",
        type=int,
        help="Optional VSSAnalysisAge value for EvtxHunter. Defaults to 0.",
    )


def add_connection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--api-client",
        help=(
            "Path to a Velociraptor API client config. Defaults to "
            "./velociraptor/api_client.yaml or DFIR_VELO_API_CLIENT."
        ),
    )
    parser.add_argument(
        "--org-id",
        default=None,
        help="Velociraptor org id to use. Defaults to root or DFIR_VELO_ORG_ID.",
    )


def add_poll_args(
    parser: argparse.ArgumentParser,
    *,
    include_disable_flag: bool = False,
    default_interval_seconds: int = 15,
    default_timeout_seconds: int = 3600,
) -> None:
    if include_disable_flag:
        parser.add_argument(
            "--no-poll",
            action="store_true",
            help="Return after queue/reuse without waiting for the saved collection state to complete.",
        )
    parser.add_argument(
        "--poll-interval-seconds",
        type=int,
        default=default_interval_seconds,
        help="How long to wait between status refreshes when polling the saved collection state.",
    )
    parser.add_argument(
        "--poll-timeout-seconds",
        type=int,
        default=default_timeout_seconds,
        help="Maximum total wait time when polling for collection completion.",
    )


def add_export_args(
    parser: argparse.ArgumentParser,
    *,
    include_disable_flag: bool = False,
) -> None:
    if include_disable_flag:
        parser.add_argument(
            "--no-export",
            action="store_true",
            help="Do not automatically export finished collection results to CSV after the action completes.",
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Queue, inspect, or export per-artifact Windows host collections."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    queue_cmd = subparsers.add_parser("queue", help="Queue one new Velociraptor flow per requested artifact")
    queue_cmd.add_argument("--investigation-id", required=True, help="Case folder name under ./investigations")
    queue_cmd.add_argument("--host", required=True, help="Hostname to collect")
    add_connection_args(queue_cmd)
    add_target_args(queue_cmd)
    add_timeline_args(queue_cmd)
    queue_cmd.add_argument("--timeout-seconds", type=int, default=60, help="How long to wait for each new flow id")
    add_poll_args(queue_cmd, include_disable_flag=True)
    add_export_args(queue_cmd, include_disable_flag=True)

    check_cmd = subparsers.add_parser(
        "check",
        help="Check whether matching per-artifact collection flows already exist for the requested target",
    )
    check_cmd.add_argument("--investigation-id", required=True, help="Case folder name under ./investigations")
    check_cmd.add_argument("--host", required=True, help="Hostname to inspect")
    add_connection_args(check_cmd)
    add_target_args(check_cmd)
    add_timeline_args(check_cmd)

    ensure_cmd = subparsers.add_parser(
        "ensure",
        help="Reuse matching per-artifact flows, or queue new ones when they are missing",
    )
    ensure_cmd.add_argument("--investigation-id", required=True, help="Case folder name under ./investigations")
    ensure_cmd.add_argument("--host", required=True, help="Hostname to collect or inspect")
    add_connection_args(ensure_cmd)
    add_target_args(ensure_cmd)
    add_timeline_args(ensure_cmd)
    ensure_cmd.add_argument("--timeout-seconds", type=int, default=60, help="How long to wait for each new flow id")
    ensure_cmd.add_argument(
        "--force-run",
        action="store_true",
        help="Queue a fresh flow per artifact even when matching prior collections already exist.",
    )
    add_poll_args(ensure_cmd, include_disable_flag=True)
    add_export_args(ensure_cmd, include_disable_flag=True)

    export_cmd = subparsers.add_parser(
        "export",
        help="Export finished collection results to CSV files under the host's velociraptor/exports/ folder",
    )
    export_cmd.add_argument("--investigation-id", required=True, help="Case folder name under ./investigations")
    export_cmd.add_argument("--host", required=True, help="Hostname to export")
    add_connection_args(export_cmd)
    add_request_id_arg(export_cmd)
    add_target_args(export_cmd)
    add_timeline_args(export_cmd)

    export_registry_cmd = subparsers.add_parser(
        "export-registry-hunter",
        help="Export curated Registry Hunter CSV views from a finished Windows.Registry.Hunter[all] flow",
    )
    export_registry_cmd.add_argument("--investigation-id", required=True, help="Case folder name under ./investigations")
    export_registry_cmd.add_argument("--host", required=True, help="Hostname to export")
    add_connection_args(export_registry_cmd)
    export_registry_cmd.add_argument(
        "--profile",
        choices=sorted(REGISTRY_HUNTER_CURATED_PROFILES),
        default="execution",
        help="Curated Registry Hunter export profile to run.",
    )

    status_cmd = subparsers.add_parser("status", help="Refresh the saved per-artifact collection status")
    status_cmd.add_argument("--investigation-id", required=True, help="Case folder name under ./investigations")
    status_cmd.add_argument("--host", required=True, help="Hostname to inspect")
    add_connection_args(status_cmd)
    add_request_id_arg(status_cmd)

    poll_cmd = subparsers.add_parser(
        "poll",
        help="Poll the saved per-artifact collection state until all requested artifacts are complete",
    )
    poll_cmd.add_argument("--investigation-id", required=True, help="Case folder name under ./investigations")
    poll_cmd.add_argument("--host", required=True, help="Hostname to inspect")
    add_connection_args(poll_cmd)
    add_request_id_arg(poll_cmd)
    poll_cmd.add_argument(
        "--interval-seconds",
        type=int,
        default=15,
        help="How long to wait between status refreshes.",
    )
    poll_cmd.add_argument(
        "--timeout-seconds",
        type=int,
        default=3600,
        help="Maximum total wait time before returning the latest incomplete status.",
    )
    add_export_args(poll_cmd, include_disable_flag=True)

    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        api_client = Path(
            args.api_client
            or os.environ.get("DFIR_VELO_API_CLIENT")
            or DEFAULT_API_CLIENT
        ).expanduser()
        org_id = args.org_id or os.environ.get("DFIR_VELO_ORG_ID") or DEFAULT_ORG_ID
        if not api_client.exists():
            print(f"API client config not found at {api_client}", file=sys.stderr)
            return 1

        with VeloApiClient(api_client, org_id=org_id) as api:
            if args.command == "status":
                payload = status_payload(api, args.investigation_id, args.host, request_id=args.request_id)
            elif args.command == "poll":
                payload = poll_collection(
                    api,
                    args.investigation_id,
                    args.host,
                    args.interval_seconds,
                    args.timeout_seconds,
                    request_id=args.request_id,
                )
                request = resolve_export_request(args, args.investigation_id, args.host)
                payload = maybe_export_after_collection(
                    api,
                    payload,
                    args.investigation_id,
                    args.host,
                    request,
                    not args.no_export,
                )
            elif args.command == "export":
                request = resolve_export_request(args, args.investigation_id, args.host)
                payload = export_collection(api, args.investigation_id, args.host, request)
            elif args.command == "export-registry-hunter":
                payload = export_registry_hunter_curated_profile(
                    api,
                    args.investigation_id,
                    args.host,
                    args.profile,
                )
            else:
                request = build_request_from_args(args)
                if args.command == "queue":
                    payload = queue_collection(api, args.investigation_id, args.host, request, args.timeout_seconds)
                    payload = maybe_poll_after_collection(
                        api,
                        payload,
                        args.investigation_id,
                        args.host,
                        not args.no_poll,
                        args.poll_interval_seconds,
                        args.poll_timeout_seconds,
                    )
                    payload = maybe_export_after_collection(
                        api,
                        payload,
                        args.investigation_id,
                        args.host,
                        request,
                        not args.no_export,
                    )
                elif args.command == "check":
                    payload = check_collection(api, args.investigation_id, args.host, request)
                else:
                    payload = ensure_collection(
                        api,
                        args.investigation_id,
                        args.host,
                        request,
                        args.timeout_seconds,
                        args.force_run,
                    )
                    payload = maybe_poll_after_collection(
                        api,
                        payload,
                        args.investigation_id,
                        args.host,
                        not args.no_poll,
                        args.poll_interval_seconds,
                        args.poll_timeout_seconds,
                    )
                    payload = maybe_export_after_collection(
                        api,
                        payload,
                        args.investigation_id,
                        args.host,
                        request,
                        not args.no_export,
                    )

        print(json.dumps(payload, indent=2, sort_keys=False))
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
