# SIEM — Real-Time Security Log Analysis Tool

A complete, working SIEM in pure Python (no dependencies). Regex-driven parsing, SQLite event store, correlation + anomaly detection, automated alerting with active response, and a live web dashboard.

## Quick start

```bash
python run.py --demo          # built-in attack simulator — instant demo
# open http://127.0.0.1:8787
```

Monitor real logs:

```bash
python run.py -f /var/log/auth.log -f /var/log/nginx/access.log
```

Receive syslog from other machines (enabled by default in `config.json`, port 5514 udp+tcp):

```bash
# on a remote box:
logger -n <siem-host> -P 5514 -d "test message"
```

## Features

**Ingestion**
- File tailing with log-rotation handling (`tail -F` semantics), multiple files
- Network syslog server (UDP + TCP)
- Demo attack simulator — generates baseline traffic plus brute-force, web attacks, port scans, sudo abuse, credential compromise, and recon bursts so every detection rule can be demonstrated

**Parsing (regex-driven, normalized events)**
- SSH (failed/accepted logins, invalid users), sudo (commands + auth failures)
- Nginx/Apache access logs with inline web-attack classification (SQLi, XSS, path traversal, command injection, sensitive-file probes, scanner user-agents)
- UFW/iptables firewall blocks, kernel errors (segfault, OOM)
- Windows event exports (4624/4625/4672/4720/4740/1102/7045)
- User-extensible signature rules in `rules/signatures.json` (reverse shells, crypto miners, SSH-key persistence, sudoers tampering…)

**Detection**
- Brute-force (N failures / window per IP)
- Credential compromise (success immediately after repeated failures) — critical
- Port scan (distinct ports per source IP)
- Privilege-escalation attempts (repeated sudo failures)
- Web attack & scanner detection, HTTP 4xx/5xx recon bursts
- Statistical anomaly detection: EWMA baseline per source, z-score spike alerts
- Alert deduplication with configurable cooldown

**Alerting & response**
- Severity levels info→critical, stored in SQLite, live-pushed to dashboard
- Webhook notifications (Slack/Discord/generic JSON), SMTP email
- Active response: auto-blocklist attacking IPs, optional firewall command hook
  (`"block_command": "iptables -A INPUT -s {ip} -j DROP"`)

**Dashboard (http://127.0.0.1:8787)**
- Real-time event stream via Server-Sent Events, events/sec counter
- Charts: event volume (30 min), alerts by severity, top source IPs
- Searchable event explorer (text/severity/type/IP filters)
- Alert feed with acknowledge, blocklist management (unblock)

**Ops**
- SQLite WAL mode, indexed queries, automatic retention purge (`retention_days`)
- Everything configurable in `config.json`; sensible defaults; zero pip installs

## REST API

`GET /api/stats` · `GET /api/events?q=&type=&severity=&ip=&since=&limit=` ·
`GET /api/alerts?open=1` · `POST /api/alerts/ack {"id":1}` ·
`GET /api/blocklist` · `POST /api/blocklist/remove {"ip":"1.2.3.4"}` · `GET /stream` (SSE)

## Layout

```
run.py                  entry point / CLI
config.json             all settings
rules/signatures.json   custom regex signatures
siem/
  events.py    event/alert models + pub-sub bus
  parser.py    regex parsing & normalization
  detect.py    correlation + anomaly engine
  storage.py   SQLite backend
  alerts.py    notifiers + active response
  ingest.py    tailer / syslog / demo generator
  server.py    REST API + SSE
  dashboard.html
```

## Ideas for the next iteration

GeoIP enrichment of attacker IPs, threat-intel feed lookups (AbuseIPDB/OTX), Sigma rule import, MITRE ATT&CK tagging on alerts, multi-host agent → central collector mode, and role-based auth on the dashboard.
