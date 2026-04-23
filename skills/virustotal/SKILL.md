---
name: virustotal
description: Enrich hashes, URLs, IPs, and domains with VirusTotal using a repo-local Python CLI that mirrors the mcp-virustotal tool surface. Use when you need VirusTotal report or relationship lookups for case indicators and want env-first API key handling with config-file fallback.
---

# VirusTotal

Use this skill to enrich case indicators with VirusTotal from the repo root.

## Configuration

API key resolution order:

1. `VIRUSTOTAL_API_KEY` environment variable
2. repo-local `./virustotal-config.json`
3. user-local `~/.config/dfir-skills/virustotal-config.json`

Config file format:

```json
{
  "api_key": "your-virustotal-api-key"
}
```

The repo-local config file is gitignored and may also include optional
`base_url` and `timeout` keys.

## Tool Surface

This skill mirrors these tool names from the referenced `mcp-virustotal`
server:

- `get_url_report`
- `get_url_relationship`
- `get_file_report`
- `get_file_relationship`
- `get_ip_report`
- `get_ip_relationship`
- `get_domain_report`
- `get_domain_relationship`

The helper script is:

```bash
python3 /Users/matt/git/dfir-skills/skills/virustotal/scripts/virustotal_cli.py --help
```

List the available tools and relationship sets:

```bash
python3 /Users/matt/git/dfir-skills/skills/virustotal/scripts/virustotal_cli.py list_tools
```

## Commands

Save a file report into a case folder:

```bash
mkdir -p /Users/matt/git/dfir-skills/investigations/shieldbase-intrusion/evidence/virustotal
python3 /Users/matt/git/dfir-skills/skills/virustotal/scripts/virustotal_cli.py \
  get_file_report \
  --hash 87c8fa606729ed63cb9d59f6b731338f8b06addbb3ef91e99b773eac2f2c524d \
  --output /Users/matt/git/dfir-skills/investigations/shieldbase-intrusion/evidence/virustotal/base-dc-subject-srv-file-report.json
```

Fetch a detailed file relationship:

```bash
python3 /Users/matt/git/dfir-skills/skills/virustotal/scripts/virustotal_cli.py \
  get_file_relationship \
  --hash 87c8fa606729ed63cb9d59f6b731338f8b06addbb3ef91e99b773eac2f2c524d \
  --relationship related_threat_actors \
  --limit 10
```

Save a domain report with explicit relationships:

```bash
python3 /Users/matt/git/dfir-skills/skills/virustotal/scripts/virustotal_cli.py \
  get_domain_report \
  --domain example.com \
  --relationships historical_whois historical_ssl_certificates resolutions urls \
  --output /Users/matt/git/dfir-skills/investigations/shieldbase-intrusion/evidence/virustotal/example-com-domain-report.json
```

Fetch an IP relationship with pagination:

```bash
python3 /Users/matt/git/dfir-skills/skills/virustotal/scripts/virustotal_cli.py \
  get_ip_relationship \
  --ip 8.8.8.8 \
  --relationship urls \
  --limit 20 \
  --cursor '<cursor-from-previous-result>'
```

Scan and report on a URL:

```bash
python3 /Users/matt/git/dfir-skills/skills/virustotal/scripts/virustotal_cli.py \
  get_url_report \
  --url https://example.com/ \
  --output /Users/matt/git/dfir-skills/investigations/shieldbase-intrusion/evidence/virustotal/example-url-report.json
```

## Workflow

1. Save raw VT results under `./investigations/<investigation_id>/evidence/virustotal/`.
2. Use report commands first for a broad view.
3. Use relationship commands when the report surfaces a specific pivot.
4. Promote useful hashes, domains, IPs, URLs, comments, collections, votes, or
   related threat-actor links into the investigation Spreadsheet of Doom and
   `./investigations/<investigation_id>/wiki/analysis.md` when they materially
   change the case.
5. Keep the exact VT object type clear in the wiki so later review can tell
   whether an insight came from a file, URL, domain, or IP report.
6. Skip internal domains such as `*.shieldbase.lan` and other obviously
   internal-only names by default. Record them as internal infrastructure
   instead of treating the VT miss as meaningful.
7. Treat RFC1918 private IPs as low-value VT pivots by default. If you do
   query them, record that they are private and interpret any VT result
   cautiously.

## Notes

- `get_url_report` submits the URL for analysis, polls the analysis record, and
  then fetches the URL object plus default relationships.
- Report commands automatically fetch default relationship sets modeled on the
  referenced `mcp-virustotal` tool.
- Relationship commands support `limit` and `cursor` pagination.
- Use `--config /path/to/config.json` to override the default config path
  search order for a single run.
- Many IOC types used in DFIR casework, such as usernames, services, task
  names, command lines, UNC paths, registry paths, and PDB paths, are not
  native VT object types. Mark them as unsupported rather than forcing them
  into a poor enrichment path.
