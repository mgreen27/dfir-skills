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
DEFAULT_REPO_CONFIG = REPO_ROOT / "config.json"
DEFAULT_TIMEOUT = 60
DEFAULT_RELATIONSHIP_LIMIT = 20

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
        candidates.append(DEFAULT_REPO_CONFIG)

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
            searched.append(str(DEFAULT_REPO_CONFIG))
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
    value = (
        value.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
        .replace("(.)", ".")
    )
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
    value = value.replace("[.]", ".").replace("(.)", ".")
    if not re.fullmatch(r"([A-Za-z0-9-]+\.)+[A-Za-z]{2,}", value):
        raise argparse.ArgumentTypeError("must be a valid domain name")
    return value.lower()


def compact_dict(mapping: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in mapping.items()
        if value not in (None, "", [], {})
    }


def build_verdict(stats: dict[str, Any]) -> str:
    if stats.get("malicious", 0):
        return "malicious"
    if stats.get("suspicious", 0):
        return "suspicious"
    return "not_flagged"


def build_analysis_summary(stats: dict[str, Any]) -> dict[str, Any]:
    return compact_dict(
        {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "failure": stats.get("failure", 0),
            "type_unsupported": stats.get("type-unsupported", 0),
        }
    )


def summarize_certificate(cert: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(cert, dict):
        return {}

    subject = cert.get("subject", {}) if isinstance(cert.get("subject"), dict) else {}
    issuer = cert.get("issuer", {}) if isinstance(cert.get("issuer"), dict) else {}
    validity = cert.get("validity", {}) if isinstance(cert.get("validity"), dict) else {}
    public_key = cert.get("public_key", {}) if isinstance(cert.get("public_key"), dict) else {}
    rsa_key = public_key.get("rsa", {}) if isinstance(public_key.get("rsa"), dict) else {}
    extensions = cert.get("extensions", {}) if isinstance(cert.get("extensions"), dict) else {}

    return compact_dict(
        {
            "subject_cn": subject.get("CN"),
            "subject_org": subject.get("O"),
            "issuer_cn": issuer.get("CN"),
            "issuer_org": issuer.get("O"),
            "thumbprint_sha256": cert.get("thumbprint_sha256"),
            "serial_number": cert.get("serial_number"),
            "valid_from": validity.get("not_before"),
            "valid_to": validity.get("not_after"),
            "public_key_algorithm": public_key.get("algorithm"),
            "key_size": rsa_key.get("key_size"),
            "san": list(extensions.get("subject_alternative_name", []))[:10] if isinstance(extensions.get("subject_alternative_name"), list) else None,
        }
    )


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


def build_url_gui_link(url_id: str | None) -> str | None:
    if not url_id:
        return None
    return f"https://www.virustotal.com/gui/url/{url_id}/"


def build_ip_gui_link(ip_value: str | None) -> str | None:
    if not ip_value:
        return None
    return f"https://www.virustotal.com/gui/ip-address/{ip_value}/"


def build_domain_gui_link(domain_value: str | None) -> str | None:
    if not domain_value:
        return None
    return f"https://www.virustotal.com/gui/domain/{domain_value}/"


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
            "verdict": build_verdict(stats),
            "analysis": build_analysis_summary(stats),
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
    }
    return summary


def build_url_report_summary(payload: dict[str, Any]) -> dict[str, Any]:
    report_data = _safe_get(payload, "report", "data") or {}
    if not isinstance(report_data, dict):
        raise VirusTotalClientError("Unexpected URL report shape for summary output")
    attributes = report_data.get("attributes", {})
    if not isinstance(attributes, dict):
        raise VirusTotalClientError("Unexpected URL report attributes for summary output")

    report_id = report_data.get("id")
    stats = attributes.get("last_analysis_stats", {}) if isinstance(attributes.get("last_analysis_stats"), dict) else {}
    categories = attributes.get("categories", {})
    categories_list = list(categories.values()) if isinstance(categories, dict) else []

    return compact_dict(
        {
            "tool": payload.get("tool"),
            "retrieved_at": payload.get("retrieved_at"),
            "input": payload.get("input"),
            "url_link": build_url_gui_link(report_id),
            "summary": compact_dict(
                {
                    "id": report_id,
                    "url": attributes.get("url"),
                    "title": attributes.get("title"),
                    "verdict": build_verdict(stats),
                    "analysis": build_analysis_summary(stats),
                    "reputation": attributes.get("reputation"),
                    "categories": categories_list,
                    "tags": list(attributes.get("tags", []))[:10],
                }
            ),
            "details_summary": compact_dict(
                {
                    "url": attributes.get("url"),
                    "last_final_url": attributes.get("last_final_url"),
                    "title": attributes.get("title"),
                    "times_submitted": attributes.get("times_submitted"),
                    "total_votes": attributes.get("total_votes"),
                }
            ),
            "telemetry_summary": compact_dict(
                {
                    "first_submission_date": epoch_to_iso(attributes.get("first_submission_date")),
                    "last_submission_date": epoch_to_iso(attributes.get("last_submission_date")),
                    "last_analysis_date": epoch_to_iso(attributes.get("last_analysis_date")),
                    "last_modification_date": epoch_to_iso(attributes.get("last_modification_date")),
                }
            ),
        }
    )


def build_ip_report_summary(payload: dict[str, Any]) -> dict[str, Any]:
    report_data = _safe_get(payload, "report", "data") or {}
    if not isinstance(report_data, dict):
        raise VirusTotalClientError("Unexpected IP report shape for summary output")
    attributes = report_data.get("attributes", {})
    if not isinstance(attributes, dict):
        raise VirusTotalClientError("Unexpected IP report attributes for summary output")

    report_id = report_data.get("id")
    stats = attributes.get("last_analysis_stats", {}) if isinstance(attributes.get("last_analysis_stats"), dict) else {}

    return compact_dict(
        {
            "tool": payload.get("tool"),
            "retrieved_at": payload.get("retrieved_at"),
            "input": payload.get("input"),
            "ip_link": build_ip_gui_link(report_id),
            "summary": compact_dict(
                {
                    "id": report_id,
                    "verdict": build_verdict(stats),
                    "analysis": build_analysis_summary(stats),
                    "reputation": attributes.get("reputation"),
                    "country": attributes.get("country"),
                    "continent": attributes.get("continent"),
                    "network": attributes.get("network"),
                    "as_owner": attributes.get("as_owner"),
                    "asn": attributes.get("asn"),
                    "tags": list(attributes.get("tags", []))[:10],
                }
            ),
            "details_summary": compact_dict(
                {
                    "regional_internet_registry": attributes.get("regional_internet_registry"),
                    "jarm": attributes.get("jarm"),
                    "certificate_summary": summarize_certificate(
                        attributes.get("last_https_certificate")
                    ),
                    "last_https_certificate_date": epoch_to_iso(attributes.get("last_https_certificate_date")),
                    "last_modification_date": epoch_to_iso(attributes.get("last_modification_date")),
                    "total_votes": attributes.get("total_votes"),
                }
            ),
            "telemetry_summary": compact_dict(
                {
                    "last_analysis_date": epoch_to_iso(attributes.get("last_analysis_date")),
                    "last_modification_date": epoch_to_iso(attributes.get("last_modification_date")),
                    "whois_date": epoch_to_iso(attributes.get("whois_date")),
                }
            ),
        }
    )


def build_domain_report_summary(payload: dict[str, Any]) -> dict[str, Any]:
    report_data = _safe_get(payload, "report", "data") or {}
    if not isinstance(report_data, dict):
        raise VirusTotalClientError("Unexpected domain report shape for summary output")
    attributes = report_data.get("attributes", {})
    if not isinstance(attributes, dict):
        raise VirusTotalClientError("Unexpected domain report attributes for summary output")

    report_id = report_data.get("id")
    stats = attributes.get("last_analysis_stats", {}) if isinstance(attributes.get("last_analysis_stats"), dict) else {}

    return compact_dict(
        {
            "tool": payload.get("tool"),
            "retrieved_at": payload.get("retrieved_at"),
            "input": payload.get("input"),
            "domain_link": build_domain_gui_link(report_id),
            "summary": compact_dict(
                {
                    "id": report_id,
                    "verdict": build_verdict(stats),
                    "analysis": build_analysis_summary(stats),
                    "reputation": attributes.get("reputation"),
                    "categories": list(attributes.get("categories", {}).values()) if isinstance(attributes.get("categories"), dict) else [],
                    "creation_date": epoch_to_iso(attributes.get("creation_date")),
                    "last_update_date": epoch_to_iso(attributes.get("last_update_date")),
                    "tags": list(attributes.get("tags", []))[:10],
                }
            ),
            "details_summary": compact_dict(
                {
                    "registrar": attributes.get("registrar"),
                    "tld": attributes.get("tld"),
                    "certificate_summary": summarize_certificate(
                        attributes.get("last_https_certificate")
                    ),
                    "last_https_certificate_date": epoch_to_iso(attributes.get("last_https_certificate_date")),
                    "total_votes": attributes.get("total_votes"),
                }
            ),
            "telemetry_summary": compact_dict(
                {
                    "creation_date": epoch_to_iso(attributes.get("creation_date")),
                    "last_update_date": epoch_to_iso(attributes.get("last_update_date")),
                    "last_analysis_date": epoch_to_iso(attributes.get("last_analysis_date")),
                    "last_modification_date": epoch_to_iso(attributes.get("last_modification_date")),
                    "whois_date": epoch_to_iso(attributes.get("whois_date")),
                }
            ),
        }
    )


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
            {"name": "get_url_report", "type": "report", "raw_switch": "-raw / --raw", "relationship_command": "get_url_relationship"},
            {"name": "get_url_relationship", "type": "relationship", "relationships": list(URL_RELATIONSHIPS)},
            {"name": "get_file_report", "type": "report", "raw_switch": "-raw / --raw", "relationship_command": "get_file_relationship"},
            {"name": "get_file_relationship", "type": "relationship", "relationships": list(FILE_RELATIONSHIPS)},
            {"name": "get_ip_report", "type": "report", "raw_switch": "-raw / --raw", "relationship_command": "get_ip_relationship"},
            {"name": "get_ip_relationship", "type": "relationship", "relationships": list(IP_RELATIONSHIPS)},
            {"name": "get_domain_report", "type": "report", "raw_switch": "-raw / --raw", "relationship_command": "get_domain_relationship"},
            {"name": "get_domain_relationship", "type": "relationship", "relationships": list(DOMAIN_RELATIONSHIPS)},
        ],
        "config_precedence": [
            "VIRUSTOTAL_API_KEY environment variable",
            str(DEFAULT_REPO_CONFIG),
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
    payload = {
        "tool": "get_url_report",
        "retrieved_at": now_utc(),
        "input": {"url": args.url},
        "analysis_id": analysis_id,
        "analysis": analysis,
        "report": basic_report,
    }
    if args.raw:
        return payload
    return build_url_report_summary(payload)


def handle_get_url_relationship(args: argparse.Namespace) -> Any:
    client = build_client(args)
    encoded_url = encode_url_for_vt(args.url)
    relationship = resolve_relationship_arg(args)
    result = relationship_response(
        client,
        "urls",
        encoded_url,
        relationship,
        limit=args.limit,
        cursor=args.cursor,
    )
    return {
        "tool": "get_url_relationship",
        "retrieved_at": now_utc(),
        "input": {"url": args.url, "relationship": relationship, "limit": args.limit, "cursor": args.cursor},
        "relationship_result": result,
    }


def handle_get_file_report(args: argparse.Namespace) -> Any:
    client = build_client(args)
    basic_report = client.request_json("GET", f"/files/{args.hash}")
    payload = {
        "tool": "get_file_report",
        "retrieved_at": now_utc(),
        "input": {"hash": args.hash},
        "report": basic_report,
    }
    if args.raw:
        return payload
    return build_file_report_summary(payload)


def handle_get_file_relationship(args: argparse.Namespace) -> Any:
    client = build_client(args)
    relationship = resolve_relationship_arg(args)
    result = relationship_response(
        client,
        "files",
        args.hash,
        relationship,
        limit=args.limit,
        cursor=args.cursor,
    )
    return {
        "tool": "get_file_relationship",
        "retrieved_at": now_utc(),
        "input": {"hash": args.hash, "relationship": relationship, "limit": args.limit, "cursor": args.cursor},
        "relationship_result": result,
    }


def handle_get_ip_report(args: argparse.Namespace) -> Any:
    client = build_client(args)
    basic_report = client.request_json("GET", f"/ip_addresses/{args.ip}")
    payload = {
        "tool": "get_ip_report",
        "retrieved_at": now_utc(),
        "input": {"ip": args.ip},
        "report": basic_report,
    }
    if args.raw:
        return payload
    return build_ip_report_summary(payload)


def handle_get_ip_relationship(args: argparse.Namespace) -> Any:
    client = build_client(args)
    relationship = resolve_relationship_arg(args)
    result = relationship_response(
        client,
        "ip_addresses",
        args.ip,
        relationship,
        limit=args.limit,
        cursor=args.cursor,
    )
    return {
        "tool": "get_ip_relationship",
        "retrieved_at": now_utc(),
        "input": {"ip": args.ip, "relationship": relationship, "limit": args.limit, "cursor": args.cursor},
        "relationship_result": result,
    }


def handle_get_domain_report(args: argparse.Namespace) -> Any:
    client = build_client(args)
    basic_report = client.request_json("GET", f"/domains/{args.domain}")
    payload = {
        "tool": "get_domain_report",
        "retrieved_at": now_utc(),
        "input": {"domain": args.domain},
        "report": basic_report,
    }
    if args.raw:
        return payload
    return build_domain_report_summary(payload)


def handle_get_domain_relationship(args: argparse.Namespace) -> Any:
    client = build_client(args)
    relationship = resolve_relationship_arg(args)
    result = relationship_response(
        client,
        "domains",
        args.domain,
        relationship,
        limit=args.limit,
        cursor=args.cursor,
    )
    return {
        "tool": "get_domain_relationship",
        "retrieved_at": now_utc(),
        "input": {"domain": args.domain, "relationship": relationship, "limit": args.limit, "cursor": args.cursor},
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


def add_relationship_selector(parser: argparse.ArgumentParser, choices: Iterable[str]) -> None:
    allowed = tuple(choices)
    parser.add_argument("relationship", nargs="?", choices=allowed, help="Relationship type to query")
    parser.add_argument("--relationship", dest="relationship_flag", choices=allowed, help=argparse.SUPPRESS)


def resolve_relationship_arg(args: argparse.Namespace) -> str:
    relationship = getattr(args, "relationship", None) or getattr(args, "relationship_flag", None)
    if not relationship:
        raise VirusTotalClientError("relationship is required")
    return relationship


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Repo-local VirusTotal CLI mirroring the mcp-virustotal tool surface.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_tools = subparsers.add_parser("list_tools", help="List the available VirusTotal tool names and relationship sets")
    list_tools.set_defaults(handler=handle_list_tools)

    url_report = subparsers.add_parser("get_url_report", help="Get a compact URL report")
    add_common_command_args(url_report)
    url_report.add_argument("--url", required=True, type=validate_url, help="The URL to analyze")
    url_report.add_argument("--poll-timeout", type=int, default=60, help="How long to wait for URL analysis completion")
    url_report.add_argument("--poll-interval", type=int, default=3, help="Polling interval in seconds for URL analysis")
    url_report.add_argument(
        "-raw",
        "--raw",
        action="store_true",
        help="Return the full raw VirusTotal payload instead of the default compact URL summary",
    )
    url_report.set_defaults(handler=handle_get_url_report)

    url_rel = subparsers.add_parser("get_url_relationship", help="Get a specific URL relationship")
    add_common_command_args(url_rel)
    url_rel.add_argument("--url", required=True, type=validate_url, help="The URL to analyze")
    add_relationship_selector(url_rel, URL_RELATIONSHIPS)
    add_relationship_args(url_rel)
    url_rel.set_defaults(handler=handle_get_url_relationship)

    file_report = subparsers.add_parser("get_file_report", help="Get a compact file report")
    add_common_command_args(file_report)
    file_report.add_argument("--hash", required=True, type=validate_hash, help="MD5, SHA-1, or SHA-256 hash")
    file_report.add_argument(
        "-raw",
        "--raw",
        action="store_true",
        help="Return the full raw VirusTotal payload instead of the default compact file summary",
    )
    file_report.set_defaults(handler=handle_get_file_report)

    file_rel = subparsers.add_parser("get_file_relationship", help="Get a specific file relationship")
    add_common_command_args(file_rel)
    file_rel.add_argument("--hash", required=True, type=validate_hash, help="MD5, SHA-1, or SHA-256 hash")
    add_relationship_selector(file_rel, FILE_RELATIONSHIPS)
    add_relationship_args(file_rel)
    file_rel.set_defaults(handler=handle_get_file_relationship)

    ip_report = subparsers.add_parser("get_ip_report", help="Get a compact IP report")
    add_common_command_args(ip_report)
    ip_report.add_argument("--ip", required=True, type=validate_ip, help="IP address to analyze")
    ip_report.add_argument(
        "-raw",
        "--raw",
        action="store_true",
        help="Return the full raw VirusTotal payload instead of the default compact IP summary",
    )
    ip_report.set_defaults(handler=handle_get_ip_report)

    ip_rel = subparsers.add_parser("get_ip_relationship", help="Get a specific IP relationship")
    add_common_command_args(ip_rel)
    ip_rel.add_argument("--ip", required=True, type=validate_ip, help="IP address to analyze")
    add_relationship_selector(ip_rel, IP_RELATIONSHIPS)
    add_relationship_args(ip_rel)
    ip_rel.set_defaults(handler=handle_get_ip_relationship)

    domain_report = subparsers.add_parser("get_domain_report", help="Get a compact domain report")
    add_common_command_args(domain_report)
    domain_report.add_argument("--domain", required=True, type=validate_domain, help="Domain name to analyze")
    domain_report.add_argument(
        "-raw",
        "--raw",
        action="store_true",
        help="Return the full raw VirusTotal payload instead of the default compact domain summary",
    )
    domain_report.set_defaults(handler=handle_get_domain_report)

    domain_rel = subparsers.add_parser("get_domain_relationship", help="Get a specific domain relationship")
    add_common_command_args(domain_rel)
    domain_rel.add_argument("--domain", required=True, type=validate_domain, help="Domain name to analyze")
    add_relationship_selector(domain_rel, DOMAIN_RELATIONSHIPS)
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
