#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib import error, parse, request

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_REPO_CONFIG = REPO_ROOT / "virustotal-config.json"
DEFAULT_USER_CONFIG = Path.home() / ".config" / "dfir-skills" / "virustotal-config.json"
DEFAULT_TIMEOUT = 60
DEFAULT_RELATIONSHIP_LIMIT = 10

URL_RELATIONSHIPS = (
    "analyses",
    "comments",
    "communicating_files",
    "contacted_domains",
    "contacted_ips",
    "downloaded_files",
    "graphs",
    "last_serving_ip_address",
    "network_location",
    "referrer_files",
    "referrer_urls",
    "redirecting_urls",
    "redirects_to",
    "related_comments",
    "related_references",
    "related_threat_actors",
    "submissions",
)

FILE_RELATIONSHIPS = (
    "analyses",
    "behaviours",
    "bundled_files",
    "carbonblack_children",
    "carbonblack_parents",
    "ciphered_bundled_files",
    "ciphered_parents",
    "clues",
    "collections",
    "comments",
    "compressed_parents",
    "contacted_domains",
    "contacted_ips",
    "contacted_urls",
    "dropped_files",
    "email_attachments",
    "email_parents",
    "embedded_domains",
    "embedded_ips",
    "embedded_urls",
    "execution_parents",
    "graphs",
    "itw_domains",
    "itw_ips",
    "itw_urls",
    "memory_pattern_domains",
    "memory_pattern_ips",
    "memory_pattern_urls",
    "overlay_children",
    "overlay_parents",
    "pcap_children",
    "pcap_parents",
    "pe_resource_children",
    "pe_resource_parents",
    "related_references",
    "related_threat_actors",
    "similar_files",
    "submissions",
    "screenshots",
    "urls_for_embedded_js",
    "votes",
)

IP_RELATIONSHIPS = (
    "comments",
    "communicating_files",
    "downloaded_files",
    "graphs",
    "historical_ssl_certificates",
    "historical_whois",
    "related_comments",
    "related_references",
    "related_threat_actors",
    "referrer_files",
    "resolutions",
    "urls",
)

DOMAIN_RELATIONSHIPS = (
    "caa_records",
    "cname_records",
    "comments",
    "communicating_files",
    "downloaded_files",
    "historical_ssl_certificates",
    "historical_whois",
    "immediate_parent",
    "mx_records",
    "ns_records",
    "parent",
    "referrer_files",
    "related_comments",
    "related_references",
    "related_threat_actors",
    "resolutions",
    "soa_records",
    "siblings",
    "subdomains",
    "urls",
    "user_votes",
)

DEFAULT_URL_REPORT_RELATIONSHIPS = (
    "communicating_files",
    "contacted_domains",
    "contacted_ips",
    "downloaded_files",
    "redirects_to",
    "redirecting_urls",
    "related_threat_actors",
)

DEFAULT_FILE_REPORT_RELATIONSHIPS = (
    "behaviours",
    "contacted_domains",
    "contacted_ips",
    "contacted_urls",
    "dropped_files",
    "execution_parents",
    "embedded_domains",
    "embedded_ips",
    "embedded_urls",
    "itw_domains",
    "itw_ips",
    "itw_urls",
    "related_threat_actors",
    "similar_files",
)

DEFAULT_IP_REPORT_RELATIONSHIPS = (
    "communicating_files",
    "downloaded_files",
    "historical_ssl_certificates",
    "resolutions",
    "related_threat_actors",
    "urls",
)

DEFAULT_DOMAIN_REPORT_RELATIONSHIPS = (
    "historical_whois",
    "historical_ssl_certificates",
    "resolutions",
    "communicating_files",
    "downloaded_files",
    "referrer_files",
)


class VirusTotalClientError(RuntimeError):
    pass


@dataclass
class VirusTotalClient:
    api_key: str
    base_url: str = "https://www.virustotal.com/api/v3"
    timeout: int = DEFAULT_TIMEOUT

    def request_json(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        form: dict[str, Any] | None = None,
    ) -> Any:
        url = self.base_url.rstrip("/") + endpoint
        if params:
            query = parse.urlencode({k: v for k, v in params.items() if v is not None}, doseq=True)
            url = f"{url}?{query}"

        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key,
            "user-agent": "dfir-skills-virustotal/1.0",
        }
        data = None
        if form is not None:
            headers["content-type"] = "application/x-www-form-urlencoded"
            data = parse.urlencode(form).encode("utf-8")

        req = request.Request(url, method=method.upper(), headers=headers, data=data)
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
        except error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise VirusTotalClientError(format_http_error(exc.code, raw)) from exc
        except error.URLError as exc:
            raise VirusTotalClientError(f"VirusTotal request failed: {exc.reason}") from exc

        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise VirusTotalClientError(f"VirusTotal returned non-JSON data for {endpoint}") from exc


def format_http_error(status: int, raw_body: str) -> str:
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        return f"VirusTotal API error ({status}): {raw_body.strip() or 'unknown error'}"

    message = payload.get("error", {}).get("message")
    if message:
        return f"VirusTotal API error ({status}): {message}"
    return f"VirusTotal API error ({status})"


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def epoch_to_iso(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def encode_url_for_vt(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def load_json_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise VirusTotalClientError(f"Invalid JSON in config file {path}") from exc


def resolve_config(path_override: str | None) -> tuple[dict[str, Any], Path | None]:
    candidates: list[Path] = []
    if path_override:
        candidates.append(Path(path_override).expanduser())
    else:
        candidates.extend([DEFAULT_REPO_CONFIG, DEFAULT_USER_CONFIG])

    for candidate in candidates:
        if candidate.exists():
            return load_json_file(candidate), candidate
    return {}, None


def config_lookup(config: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in config:
            return config[key]
    vt_config = config.get("virustotal")
    if isinstance(vt_config, dict):
        for key in keys:
            if key in vt_config:
                return vt_config[key]
    return None


def build_client(args: argparse.Namespace) -> VirusTotalClient:
    config, config_path = resolve_config(getattr(args, "config", None))
    api_key = os.environ.get("VIRUSTOTAL_API_KEY") or config_lookup(
        config,
        "api_key",
        "virustotal_api_key",
        "VIRUSTOTAL_API_KEY",
    )
    if not api_key:
        searched = []
        if getattr(args, "config", None):
            searched.append(str(Path(args.config).expanduser()))
        else:
            searched.extend([str(DEFAULT_REPO_CONFIG), str(DEFAULT_USER_CONFIG)])
        raise VirusTotalClientError(
            "VirusTotal API key not found. Set VIRUSTOTAL_API_KEY or add an api_key "
            f"to one of: {', '.join(searched)}"
        )

    base_url = getattr(args, "base_url", None) or config_lookup(config, "base_url") or "https://www.virustotal.com/api/v3"
    timeout = getattr(args, "timeout", None) or config_lookup(config, "timeout") or DEFAULT_TIMEOUT

    client = VirusTotalClient(api_key=str(api_key).strip(), base_url=str(base_url).strip(), timeout=int(timeout))
    client._config_path = config_path  # type: ignore[attr-defined]
    return client


def validate_url(value: str) -> str:
    parsed = parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise argparse.ArgumentTypeError("must be a valid http or https URL")
    return value


def validate_hash(value: str) -> str:
    if not re.fullmatch(r"[A-Fa-f0-9]{32,64}", value):
        raise argparse.ArgumentTypeError("must be a valid MD5, SHA-1, or SHA-256 hash")
    return value.lower()


def validate_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a valid IP address") from exc
    return value


def validate_domain(value: str) -> str:
    if not re.fullmatch(r"([A-Za-z0-9-]+\.)+[A-Za-z]{2,}", value):
        raise argparse.ArgumentTypeError("must be a valid domain name")
    return value.lower()


def write_output(payload: Any, output_path: str | None) -> None:
    data = json.dumps(payload, indent=2, sort_keys=False)
    if output_path:
        path = Path(output_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data + "\n", encoding="utf-8")
    else:
        sys.stdout.write(data + "\n")


def relationship_response(
    client: VirusTotalClient,
    object_path: str,
    identifier: str,
    relationship: str,
    *,
    limit: int | None,
    cursor: str | None,
) -> Any:
    params = {"limit": limit, "cursor": cursor}
    return client.request_json("GET", f"/{object_path}/{identifier}/{relationship}", params=params)


def fetch_relationships(
    client: VirusTotalClient,
    object_path: str,
    identifier: str,
    relationships: Iterable[str],
    *,
    limit: int = DEFAULT_RELATIONSHIP_LIMIT,
) -> dict[str, Any]:
    fetched: dict[str, Any] = {}
    for relationship in relationships:
        try:
            fetched[relationship] = relationship_response(
                client,
                object_path,
                identifier,
                relationship,
                limit=limit,
                cursor=None,
            )
        except VirusTotalClientError as exc:
            fetched[relationship] = {"error": str(exc)}
    return fetched


def _safe_get(mapping: dict[str, Any], *keys: str) -> Any:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def summarize_detection_results(attributes: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    results = attributes.get("last_analysis_results", {})
    if not isinstance(results, dict):
        return []

    scored: list[tuple[tuple[int, int, str], dict[str, Any]]] = []
    for engine, details in results.items():
        if not isinstance(details, dict):
            continue
        category = str(details.get("category") or "undetected")
        result = details.get("result")
        if category in {"malicious", "suspicious"}:
            priority = 0
        elif result:
            priority = 1
        else:
            priority = 2
        scored.append(
            (
                (priority, 0 if result else 1, engine.lower()),
                {
                    "engine": engine,
                    "category": category,
                    "result": result,
                    "method": details.get("method"),
                },
            )
        )

    scored.sort(key=lambda item: item[0])
    return [item[1] for item in scored[:limit]]


def summarize_relationship_item(item: dict[str, Any]) -> dict[str, Any]:
    attributes = item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {}
    stats = attributes.get("last_analysis_stats", {}) if isinstance(attributes.get("last_analysis_stats"), dict) else {}
    summary: dict[str, Any] = {
        "id": item.get("id"),
        "type": item.get("type"),
        "name": (
            attributes.get("meaningful_name")
            or attributes.get("name")
            or (attributes.get("names") or [None])[0]
        ),
    }

    for field in ("type_tag", "type_description", "size", "magic", "origin", "description", "status", "collection_type"):
        value = attributes.get(field)
        if value not in (None, "", [], {}):
            summary[field] = value

    if stats:
        summary["last_analysis_stats"] = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
        }

    if attributes.get("tags"):
        summary["tags"] = list(attributes.get("tags", []))[:5]

    if attributes.get("popular_threat_classification"):
        ptc = attributes["popular_threat_classification"]
        if isinstance(ptc, dict):
            summary["suggested_threat_label"] = ptc.get("suggested_threat_label")

    if attributes.get("alt_names"):
        summary["alt_names"] = list(attributes.get("alt_names", []))[:3]

    for epoch_field in ("first_submission_date", "last_submission_date", "last_seen", "first_seen_itw_date", "last_seen_itw_date"):
        iso_value = epoch_to_iso(attributes.get(epoch_field))
        if iso_value:
            summary[epoch_field] = iso_value

    return summary


def summarize_relationships(relationships: dict[str, Any], limit: int = 5) -> dict[str, Any]:
    summarized: dict[str, Any] = {}
    for relationship_name, payload in relationships.items():
        if not isinstance(payload, dict):
            continue
        if "error" in payload:
            summarized[relationship_name] = {"error": payload["error"]}
            continue
        data = payload.get("data")
        if isinstance(data, list):
            summarized[relationship_name] = {
                "count": len(data),
                "items": [summarize_relationship_item(item) for item in data[:limit] if isinstance(item, dict)],
            }
        elif isinstance(data, dict):
            summarized[relationship_name] = {
                "count": 1,
                "items": [summarize_relationship_item(data)],
            }
        else:
            summarized[relationship_name] = {"count": 0, "items": []}
    return summarized


def build_file_gui_link(file_id: str | None) -> str | None:
    if not file_id:
        return None
    return f"https://www.virustotal.com/gui/file/{file_id}/"


def build_file_report_summary(payload: dict[str, Any]) -> dict[str, Any]:
    report_data = _safe_get(payload, "report", "data") or {}
    if not isinstance(report_data, dict):
        raise VirusTotalClientError("Unexpected file report shape for summary output")
    attributes = report_data.get("attributes", {})
    if not isinstance(attributes, dict):
        raise VirusTotalClientError("Unexpected file report attributes for summary output")

    report_id = report_data.get("id")
    stats = attributes.get("last_analysis_stats", {}) if isinstance(attributes.get("last_analysis_stats"), dict) else {}
    ptc = attributes.get("popular_threat_classification", {}) if isinstance(attributes.get("popular_threat_classification"), dict) else {}
    severity = attributes.get("threat_severity", {}) if isinstance(attributes.get("threat_severity"), dict) else {}

    def top_values(entries: Any, key: str = "value", limit: int = 5) -> list[str]:
        if not isinstance(entries, list):
            return []
        values: list[str] = []
        for entry in entries[:limit]:
            if isinstance(entry, dict) and entry.get(key):
                values.append(str(entry[key]))
        return values

    summary = {
        "tool": payload.get("tool"),
        "retrieved_at": payload.get("retrieved_at"),
        "input": payload.get("input"),
        "file_link": build_file_gui_link(report_id),
        "summary": {
            "id": report_id,
            "meaningful_name": attributes.get("meaningful_name"),
            "type_description": attributes.get("type_description"),
            "verdict": "malicious" if stats.get("malicious", 0) else ("suspicious" if stats.get("suspicious", 0) else "not_flagged"),
            "analysis": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "failure": stats.get("failure", 0),
                "type_unsupported": stats.get("type-unsupported", 0),
            },
            "reputation": attributes.get("reputation"),
            "threat_severity_level": severity.get("threat_severity_level"),
            "threat_severity_summary": severity.get("level_description"),
            "suggested_threat_label": ptc.get("suggested_threat_label"),
            "threat_categories": top_values(ptc.get("popular_threat_category")),
            "family_labels": top_values(ptc.get("popular_threat_name")),
            "tags": list(attributes.get("tags", []))[:10],
        },
        "details_summary": {
            "sha256": attributes.get("sha256") or report_id,
            "sha1": attributes.get("sha1"),
            "md5": attributes.get("md5"),
            "size": attributes.get("size"),
            "type_tag": attributes.get("type_tag"),
            "type_extension": attributes.get("type_extension"),
            "magika": attributes.get("magika"),
            "magic": attributes.get("magic"),
            "meaningful_name": attributes.get("meaningful_name"),
            "names": list(attributes.get("names", []))[:10],
            "downloadable": attributes.get("downloadable"),
            "times_submitted": attributes.get("times_submitted"),
            "total_votes": attributes.get("total_votes"),
        },
        "telemetry_summary": {
            "first_submission_date": epoch_to_iso(attributes.get("first_submission_date")),
            "last_submission_date": epoch_to_iso(attributes.get("last_submission_date")),
            "first_seen_itw_date": epoch_to_iso(attributes.get("first_seen_itw_date")),
            "last_seen_itw_date": epoch_to_iso(attributes.get("last_seen_itw_date")),
            "last_analysis_date": epoch_to_iso(attributes.get("last_analysis_date")),
            "last_modification_date": epoch_to_iso(attributes.get("last_modification_date")),
            "unique_sources": attributes.get("unique_sources"),
        },
        "top_detections": summarize_detection_results(attributes, limit=10),
        "relations": summarize_relationships(payload.get("relationships", {}) if isinstance(payload.get("relationships"), dict) else {}, limit=5),
    }
    return summary


def poll_analysis(client: VirusTotalClient, analysis_id: str, timeout: int, interval: int) -> Any:
    deadline = time.time() + timeout
    last_response: Any = None
    while time.time() < deadline:
        last_response = client.request_json("GET", f"/analyses/{analysis_id}")
        status = last_response.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return last_response
        time.sleep(interval)
    return last_response


def handle_list_tools(args: argparse.Namespace) -> Any:
    return {
        "tools": [
            {"name": "get_url_report", "type": "report", "default_relationships": list(DEFAULT_URL_REPORT_RELATIONSHIPS)},
            {"name": "get_url_relationship", "type": "relationship", "relationships": list(URL_RELATIONSHIPS)},
            {"name": "get_file_report", "type": "report", "default_relationships": list(DEFAULT_FILE_REPORT_RELATIONSHIPS)},
            {"name": "get_file_relationship", "type": "relationship", "relationships": list(FILE_RELATIONSHIPS)},
            {"name": "get_ip_report", "type": "report", "default_relationships": list(DEFAULT_IP_REPORT_RELATIONSHIPS)},
            {"name": "get_ip_relationship", "type": "relationship", "relationships": list(IP_RELATIONSHIPS)},
            {"name": "get_domain_report", "type": "report", "default_relationships": list(DEFAULT_DOMAIN_REPORT_RELATIONSHIPS)},
            {"name": "get_domain_relationship", "type": "relationship", "relationships": list(DOMAIN_RELATIONSHIPS)},
        ],
        "config_precedence": [
            "VIRUSTOTAL_API_KEY environment variable",
            str(DEFAULT_REPO_CONFIG),
            str(DEFAULT_USER_CONFIG),
        ],
    }


def handle_get_url_report(args: argparse.Namespace) -> Any:
    client = build_client(args)
    encoded_url = encode_url_for_vt(args.url)
    scan_response = client.request_json("POST", "/urls", form={"url": args.url})
    analysis_id = scan_response.get("data", {}).get("id")
    if not analysis_id:
        raise VirusTotalClientError("VirusTotal did not return an analysis id for the URL submission")
    analysis = poll_analysis(client, analysis_id, args.poll_timeout, args.poll_interval)
    basic_report = client.request_json("GET", f"/urls/{encoded_url}")
    relationships = fetch_relationships(
        client,
        "urls",
        encoded_url,
        DEFAULT_URL_REPORT_RELATIONSHIPS,
        limit=args.relationship_limit,
    )
    return {
        "tool": "get_url_report",
        "retrieved_at": now_utc(),
        "input": {"url": args.url},
        "analysis_id": analysis_id,
        "analysis": analysis,
        "report": basic_report,
        "relationships": relationships,
    }


def handle_get_url_relationship(args: argparse.Namespace) -> Any:
    client = build_client(args)
    encoded_url = encode_url_for_vt(args.url)
    result = relationship_response(
        client,
        "urls",
        encoded_url,
        args.relationship,
        limit=args.limit,
        cursor=args.cursor,
    )
    return {
        "tool": "get_url_relationship",
        "retrieved_at": now_utc(),
        "input": {"url": args.url, "relationship": args.relationship, "limit": args.limit, "cursor": args.cursor},
        "relationship_result": result,
    }


def handle_get_file_report(args: argparse.Namespace) -> Any:
    client = build_client(args)
    basic_report = client.request_json("GET", f"/files/{args.hash}")
    relationships = fetch_relationships(
        client,
        "files",
        args.hash,
        DEFAULT_FILE_REPORT_RELATIONSHIPS,
        limit=args.relationship_limit,
    )
    payload = {
        "tool": "get_file_report",
        "retrieved_at": now_utc(),
        "input": {"hash": args.hash},
        "report": basic_report,
        "relationships": relationships,
    }
    if args.raw:
        return payload
    return build_file_report_summary(payload)


def handle_get_file_relationship(args: argparse.Namespace) -> Any:
    client = build_client(args)
    result = relationship_response(
        client,
        "files",
        args.hash,
        args.relationship,
        limit=args.limit,
        cursor=args.cursor,
    )
    return {
        "tool": "get_file_relationship",
        "retrieved_at": now_utc(),
        "input": {"hash": args.hash, "relationship": args.relationship, "limit": args.limit, "cursor": args.cursor},
        "relationship_result": result,
    }


def handle_get_ip_report(args: argparse.Namespace) -> Any:
    client = build_client(args)
    basic_report = client.request_json("GET", f"/ip_addresses/{args.ip}")
    relationships = fetch_relationships(
        client,
        "ip_addresses",
        args.ip,
        DEFAULT_IP_REPORT_RELATIONSHIPS,
        limit=args.relationship_limit,
    )
    return {
        "tool": "get_ip_report",
        "retrieved_at": now_utc(),
        "input": {"ip": args.ip},
        "report": basic_report,
        "relationships": relationships,
    }


def handle_get_ip_relationship(args: argparse.Namespace) -> Any:
    client = build_client(args)
    result = relationship_response(
        client,
        "ip_addresses",
        args.ip,
        args.relationship,
        limit=args.limit,
        cursor=args.cursor,
    )
    return {
        "tool": "get_ip_relationship",
        "retrieved_at": now_utc(),
        "input": {"ip": args.ip, "relationship": args.relationship, "limit": args.limit, "cursor": args.cursor},
        "relationship_result": result,
    }


def handle_get_domain_report(args: argparse.Namespace) -> Any:
    client = build_client(args)
    selected_relationships = tuple(args.relationships) if args.relationships else DEFAULT_DOMAIN_REPORT_RELATIONSHIPS
    basic_report = client.request_json("GET", f"/domains/{args.domain}")
    relationships = fetch_relationships(
        client,
        "domains",
        args.domain,
        selected_relationships,
        limit=args.relationship_limit,
    )
    return {
        "tool": "get_domain_report",
        "retrieved_at": now_utc(),
        "input": {"domain": args.domain, "relationships": list(selected_relationships)},
        "report": basic_report,
        "relationships": relationships,
    }


def handle_get_domain_relationship(args: argparse.Namespace) -> Any:
    client = build_client(args)
    result = relationship_response(
        client,
        "domains",
        args.domain,
        args.relationship,
        limit=args.limit,
        cursor=args.cursor,
    )
    return {
        "tool": "get_domain_relationship",
        "retrieved_at": now_utc(),
        "input": {"domain": args.domain, "relationship": args.relationship, "limit": args.limit, "cursor": args.cursor},
        "relationship_result": result,
    }


def add_common_command_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="Path to a VirusTotal config JSON file")
    parser.add_argument("--base-url", help="Override the VirusTotal API base URL")
    parser.add_argument("--timeout", type=int, help="HTTP timeout in seconds")
    parser.add_argument("--output", help="Write JSON output to this file instead of stdout")


def add_relationship_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--limit", type=int, default=10, help="Maximum number of related objects to retrieve (1-40)")
    parser.add_argument("--cursor", help="Pagination cursor from a previous result")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Repo-local VirusTotal CLI mirroring the mcp-virustotal tool surface.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_tools = subparsers.add_parser("list_tools", help="List the available VirusTotal tool names and relationship sets")
    list_tools.set_defaults(handler=handle_list_tools)

    url_report = subparsers.add_parser("get_url_report", help="Get a URL report with default relationships")
    add_common_command_args(url_report)
    url_report.add_argument("--url", required=True, type=validate_url, help="The URL to analyze")
    url_report.add_argument("--poll-timeout", type=int, default=60, help="How long to wait for URL analysis completion")
    url_report.add_argument("--poll-interval", type=int, default=3, help="Polling interval in seconds for URL analysis")
    url_report.add_argument("--relationship-limit", type=int, default=DEFAULT_RELATIONSHIP_LIMIT, help="Per-relationship fetch limit")
    url_report.set_defaults(handler=handle_get_url_report)

    url_rel = subparsers.add_parser("get_url_relationship", help="Get a specific URL relationship")
    add_common_command_args(url_rel)
    url_rel.add_argument("--url", required=True, type=validate_url, help="The URL to analyze")
    url_rel.add_argument("--relationship", required=True, choices=URL_RELATIONSHIPS, help="Relationship type to query")
    add_relationship_args(url_rel)
    url_rel.set_defaults(handler=handle_get_url_relationship)

    file_report = subparsers.add_parser("get_file_report", help="Get a file report with default relationships")
    add_common_command_args(file_report)
    file_report.add_argument("--hash", required=True, type=validate_hash, help="MD5, SHA-1, or SHA-256 hash")
    file_report.add_argument("--relationship-limit", type=int, default=DEFAULT_RELATIONSHIP_LIMIT, help="Per-relationship fetch limit")
    file_report.add_argument(
        "--raw",
        action="store_true",
        help="Return the full raw VirusTotal payload instead of the default compact file summary",
    )
    file_report.set_defaults(handler=handle_get_file_report)

    file_rel = subparsers.add_parser("get_file_relationship", help="Get a specific file relationship")
    add_common_command_args(file_rel)
    file_rel.add_argument("--hash", required=True, type=validate_hash, help="MD5, SHA-1, or SHA-256 hash")
    file_rel.add_argument("--relationship", required=True, choices=FILE_RELATIONSHIPS, help="Relationship type to query")
    add_relationship_args(file_rel)
    file_rel.set_defaults(handler=handle_get_file_relationship)

    ip_report = subparsers.add_parser("get_ip_report", help="Get an IP report with default relationships")
    add_common_command_args(ip_report)
    ip_report.add_argument("--ip", required=True, type=validate_ip, help="IP address to analyze")
    ip_report.add_argument("--relationship-limit", type=int, default=DEFAULT_RELATIONSHIP_LIMIT, help="Per-relationship fetch limit")
    ip_report.set_defaults(handler=handle_get_ip_report)

    ip_rel = subparsers.add_parser("get_ip_relationship", help="Get a specific IP relationship")
    add_common_command_args(ip_rel)
    ip_rel.add_argument("--ip", required=True, type=validate_ip, help="IP address to analyze")
    ip_rel.add_argument("--relationship", required=True, choices=IP_RELATIONSHIPS, help="Relationship type to query")
    add_relationship_args(ip_rel)
    ip_rel.set_defaults(handler=handle_get_ip_relationship)

    domain_report = subparsers.add_parser("get_domain_report", help="Get a domain report with default or selected relationships")
    add_common_command_args(domain_report)
    domain_report.add_argument("--domain", required=True, type=validate_domain, help="Domain name to analyze")
    domain_report.add_argument("--relationships", nargs="*", choices=DOMAIN_RELATIONSHIPS, help="Optional list of relationships to include")
    domain_report.add_argument("--relationship-limit", type=int, default=DEFAULT_RELATIONSHIP_LIMIT, help="Per-relationship fetch limit")
    domain_report.set_defaults(handler=handle_get_domain_report)

    domain_rel = subparsers.add_parser("get_domain_relationship", help="Get a specific domain relationship")
    add_common_command_args(domain_rel)
    domain_rel.add_argument("--domain", required=True, type=validate_domain, help="Domain name to analyze")
    domain_rel.add_argument("--relationship", required=True, choices=DOMAIN_RELATIONSHIPS, help="Relationship type to query")
    add_relationship_args(domain_rel)
    domain_rel.set_defaults(handler=handle_get_domain_relationship)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        payload = args.handler(args)
        write_output(payload, getattr(args, "output", None))
    except VirusTotalClientError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
