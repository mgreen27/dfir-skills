---
name: virustotal
description: Enrich file hashes, URLs, IPs, and domains with VirusTotal. Use when you need a compact analyst summary by default, a raw VT object on demand, or a specific relationship pivot such as related threat actors or resolutions.
---

# VirusTotal

Use this skill from the repo root when you want VirusTotal enrichment that is
easy to review, easy to post to Slack, and small enough to keep in case data.

## Configuration

The helper reads `VIRUSTOTAL_API_KEY` first, then repo-local `./config.json`.
Keep the detailed config format in the script behavior and the real
`./config.json`, not duplicated here.

## Command Surface

Report commands return compact summaries by default:

- `get_file_report`
- `get_url_report`
- `get_ip_report`
- `get_domain_report`

Relationship commands fetch one specific VT relationship at a time:

- `get_file_relationship`
- `get_url_relationship`
- `get_ip_relationship`
- `get_domain_relationship`

Show the current tool surface:

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py list_tools
```

Show help:

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py --help
```

## Output Model

Default report output is compact and analyst-friendly. Report commands do not
fetch relationships.

Use `-raw` or `--raw` when you want the original VT object instead of the
compact summary.

Relationship commands use a positional relationship name, not a required
`--relationship` switch.

## File Report

Run:

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py \
  get_file_report \
  --hash 003b780abec3cf77df45838f40b0fa63602501499fce9fb980545003e4804c3e
```

Compact output example:

```json
{
  "tool": "get_file_report",
  "retrieved_at": "2026-04-23T23:47:48.270084+00:00",
  "input": {
    "hash": "003b780abec3cf77df45838f40b0fa63602501499fce9fb980545003e4804c3e"
  },
  "file_link": "https://www.virustotal.com/gui/file/003b780abec3cf77df45838f40b0fa63602501499fce9fb980545003e4804c3e/",
  "summary": {
    "meaningful_name": "003b780abec3cf77df45838f40b0fa63602501499fce9fb980545003e4804c3e.exe",
    "verdict": "malicious",
    "analysis": {
      "malicious": 65,
      "suspicious": 0,
      "undetected": 8
    },
    "threat_severity_level": "SEVERITY_HIGH",
    "suggested_threat_label": "trojan.cobaltstrike/barys",
    "family_labels": [
      "cobaltstrike",
      "barys",
      "cobalt"
    ]
  },
  "details_summary": {
    "sha256": "003b780abec3cf77df45838f40b0fa63602501499fce9fb980545003e4804c3e",
    "sha1": "8db7b75b0e1015cd0e00a6295c580623b0693ef3",
    "md5": "fb1eaeac9d731a6cf7a9613fb2ea6eac",
    "size": 284672,
    "type_extension": "exe",
    "type_tag": "peexe"
  },
  "telemetry_summary": {
    "first_submission_date": "2024-04-08T13:59:29+00:00",
    "last_submission_date": "2024-04-21T00:31:04+00:00",
    "first_seen_itw_date": "2024-04-08T21:10:47+00:00",
    "last_seen_itw_date": "2024-04-14T21:00:35+00:00"
  }
}
```

Raw output:

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py \
  get_file_report \
  --hash 003b780abec3cf77df45838f40b0fa63602501499fce9fb980545003e4804c3e \
  -raw
```

## URL Report

Run:

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py \
  get_url_report \
  --url 'hxxps://example[.]com/path'
```

Compact output example:

```json
{
  "tool": "get_url_report",
  "retrieved_at": "2026-04-24T00:00:00+00:00",
  "input": {
    "url": "https://example.com/path"
  },
  "url_link": "https://www.virustotal.com/gui/url/<vt-url-id>",
  "summary": {
    "verdict": "malicious",
    "analysis": {
      "malicious": 12,
      "suspicious": 1,
      "undetected": 20
    },
    "categories": {
      "Forcepoint ThreatSeeker": "malware"
    },
    "tags": [
      "phishing",
      "download"
    ]
  },
  "details_summary": {
    "title": "Example landing page",
    "final_url": "https://example.com/path",
    "times_submitted": 4
  },
  "telemetry_summary": {
    "first_submission_date": "2026-04-01T10:00:00+00:00",
    "last_submission_date": "2026-04-21T10:00:00+00:00",
    "last_analysis_date": "2026-04-21T10:03:00+00:00"
  }
}
```

Raw output:

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py \
  get_url_report \
  --url 'hxxps://example[.]com/path' \
  --raw
```

## IP Report

Run:

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py \
  get_ip_report \
  --ip 59.110.7.32
```

Compact output example:

```json
{
  "tool": "get_ip_report",
  "retrieved_at": "2026-04-24T00:00:00+00:00",
  "input": {
    "ip": "59.110.7.32"
  },
  "ip_link": "https://www.virustotal.com/gui/ip-address/59.110.7.32",
  "summary": {
    "verdict": "malicious",
    "analysis": {
      "malicious": 18,
      "suspicious": 0,
      "undetected": 28
    },
    "reputation": -18,
    "tags": [
      "c2"
    ]
  },
  "details_summary": {
    "as_owner": "Hangzhou Alibaba Advertising Co.,Ltd.",
    "country": "CN",
    "network": "59.110.0.0/16",
    "regional_internet_registry": "APNIC",
    "certificate_summary": {
      "subject_cn": "example.invalid",
      "issuer_cn": "Example CA"
    }
  },
  "telemetry_summary": {
    "last_analysis_date": "2026-04-24T00:00:00+00:00",
    "last_modification_date": "2026-04-24T00:00:00+00:00"
  }
}
```

Raw output:

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py \
  get_ip_report \
  --ip 59.110.7.32 \
  -raw
```

## Domain Report

Run:

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py \
  get_domain_report \
  --domain 'api[.]wiresguard[.]com'
```

Compact output example:

```json
{
  "tool": "get_domain_report",
  "retrieved_at": "2026-04-24T00:00:00+00:00",
  "input": {
    "domain": "api.wiresguard.com"
  },
  "domain_link": "https://www.virustotal.com/gui/domain/api.wiresguard.com",
  "summary": {
    "verdict": "malicious",
    "analysis": {
      "malicious": 22,
      "suspicious": 3,
      "undetected": 26
    },
    "reputation": -22,
    "categories": {
      "Sophos": "malware"
    }
  },
  "details_summary": {
    "tld": "com",
    "last_dns_records_date": "2026-04-21T00:00:00+00:00",
    "certificate_summary": {
      "subject_cn": "wiresguard.com",
      "issuer_cn": "WE1",
      "issuer_org": "Google Trust Services"
    }
  },
  "telemetry_summary": {
    "creation_date": "2025-11-01T00:00:00+00:00",
    "last_modification_date": "2026-04-21T00:00:00+00:00"
  }
}
```

Raw output:

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py \
  get_domain_report \
  --domain 'api[.]wiresguard[.]com' \
  --raw
```

## Relationship Commands

Relationship lookups are for follow-up pivots. Use them when the compact
report shows a reason to go deeper.

### File Relationship

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py \
  get_file_relationship \
  --hash 003b780abec3cf77df45838f40b0fa63602501499fce9fb980545003e4804c3e \
  related_threat_actors \
  --limit 10
```

Output example:

```json
{
  "tool": "get_file_relationship",
  "retrieved_at": "2026-04-24T00:00:00+00:00",
  "input": {
    "hash": "003b780abec3cf77df45838f40b0fa63602501499fce9fb980545003e4804c3e",
    "relationship": "related_threat_actors",
    "limit": 10,
    "cursor": null
  },
  "relationship_result": {
    "data": [
      {
        "type": "threat_actor",
        "id": "example-actor-id"
      }
    ]
  }
}
```

### URL Relationship

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py \
  get_url_relationship \
  --url 'hxxps://example[.]com/path' \
  contacted_ips \
  --limit 20
```

### IP Relationship

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py \
  get_ip_relationship \
  --ip 59.110.7.32 \
  urls \
  --limit 20
```

### Domain Relationship

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py \
  get_domain_relationship \
  --domain 'api[.]wiresguard[.]com' \
  related_threat_actors \
  --limit 10
```

## Saving Output

Prefer saving summaries under the case evidence tree:

```bash
mkdir -p ./investigations/<investigation_id>/evidence/virustotal
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py \
  get_file_report \
  --hash <sha256> \
  --output ./investigations/<investigation_id>/evidence/virustotal/<name>-file-report.json
```

Use raw output only when you need the full VT object for later reprocessing:

```bash
./venv/bin/python ./skills/virustotal/scripts/virustotal_cli.py \
  get_ip_report \
  --ip <ip> \
  -raw \
  --output ./investigations/<investigation_id>/evidence/virustotal/<name>-ip-report.raw.json
```

## Interpretation Notes

- `first_submission_date` is when VT first saw the object.
- `first_seen_itw_date` is when VT first associated it with in-the-wild
  delivery or hosting.
- Skip internal domains like `*.shieldbase.lan` by default.
- Treat RFC1918 private IPs as low-value VT pivots unless there is a specific
  reason to query them.
- Many DFIR indicators are not native VT objects. Do not force usernames,
  services, registry paths, or command lines into this workflow.

## Slack Posting

When posting VT results to Slack, do not paste the full JSON. Summarize the
output and use short emoji headings.

Include:

- object name or indicator
- verdict counts
- label or category if present
- first seen ITW
- last seen ITW
- VT GUI link
- one short analyst assessment line

Recommended Slack structure:

```text
:rotating_light: *VT Alert: Malicious file*
*File:* `{{summary.meaningful_name}}`
*SHA256:* `{{details_summary.sha256}}`
*Verdict:* {{summary.analysis.malicious}} malicious / {{summary.analysis.suspicious}} suspicious / {{summary.analysis.undetected}} undetected
*Label:* `{{summary.suggested_threat_label}}`
*Type:* `{{summary.type_description}}`
*First seen ITW:* `{{telemetry_summary.first_seen_itw_date}}`
*Last seen ITW:* `{{telemetry_summary.last_seen_itw_date}}`
*VT:* {{file_link}}

*Assessment:* One or two sentences only. State why the indicator matters and
what should be done next.
```

Suggested emoji headings:

- `:rotating_light:` verdict
- `:bar_chart:` detections
- `:page_facing_up:` details
- `:satellite:` telemetry
- `:mag:` assessment
