# CLI Commands

## `scan` — Full Security Scan (default)

```bash
python suvari.py scan https://example.com
```

Runs the complete pipeline:
1. **Browser analysis** — page render, SPA detection, login form check, default creds, self-registration, DOM XSS, screenshot
2. **Recon** — technology fingerprinting, port scanning, header analysis, path discovery (parallel)
3. **Tree-based scanning** — AI decides next steps, drills deeper on findings, fallback tools on failure
4. **CVE intelligence** — checks detected technologies against CVE database, generates exploit code
5. **JWT analysis** — decodes and tests any JWT tokens found
6. **AI analysis** — LLM evaluates all findings, classifies vulnerabilities
7. **Report** — markdown report with findings, evidence, remediation

### Options

| Flag | Description |
|------|-------------|
| `-f, --fast` | Quick scan (fewer tests, faster results) |
| `-s, --server` | Full server scan (SSH, FTP, SMB, DB, all ports) |
| `-l, --login` | Login credentials (username:password) |
| `-r, --source` | White-box mode (include source code analysis) |
| `-P, --parallel` | Parallel tool count (default: 3) |
| `-M, --mode` | auto \| guided \| interactive |
| `-p, --provider` | LLM provider override |
| `-m, --model` | Model name override |
| `-v, --verbose` | Verbose output |

### Examples

```bash
# Basic scan
python suvari.py scan https://example.com

# Fast scan with login
python suvari.py scan https://example.com -l admin:admin -f

# Full server scan + white-box
python suvari.py scan https://server.com -s -r ./src

# 5 parallel tools
python suvari.py scan https://example.com -P 5
```

## `recon` — Quick Reconnaissance

```bash
python suvari.py recon https://example.com
```

Runs whatweb, nmap, curl headers, and common path checks in parallel. Returns technology stack, open ports, and basic exposure.

## `attack` — Exploit Previous Findings

```bash
python suvari.py attack ./output/20260101_120000_example_com/
```

Reads `findings.json` from a previous scan and runs targeted exploitation (sqlmap, hydra, etc.) on confirmed vulnerabilities.

## `auto` — Autonomous Probability-Driven Scan

```bash
python suvari.py auto --target https://example.com
```

Seeds hypotheses, tests the most probable one each turn (read-only GET probes),
updates probabilities from the evidence, and writes a report with a decision log.
Jobs are resumable (`--resume <job-id>`, `--jobs`).

### Known-vulnerability research

After fingerprinting the stack, the loop looks up publicly known CVEs for each
detected technology. It scores how plausibly each CVE applies to *this* target,
then tests the plausible ones with harmless checks.

- **Sources** (keyless, GET only): NVD API 2.0 (by CPE where known, otherwise by
  keyword; newest records), CISA KEV (sets the exploited-in-the-wild flag), and
  optionally the GitHub Advisory DB.
- **Applicability score (0–1)** is built from these signals: version in the
  affected range, product match, affected component seen on the target
  (e.g. `/_next/image`), authentication required, KEV (+0.3), CVSS ≥ 7 (+0.2)
  and a public exploit reference (+0.15). A known version outside every affected
  range caps the score at 0.05.
- **Tests** are payload-free GETs only: version fingerprint (banner or error
  page), component reachability, missing mitigating header, and plain file
  exposure. Nothing is exploited, and DoS-class CVEs are verified by version only.
- **Caching and limits:** results are cached in `~/.cache/suvari/research/`
  (TTL 24h). NVD is limited to 5 requests per 30 s and GitHub to 60 per hour,
  with at most 60 intel requests per job. With no network, a stale cache is used;
  if there is none, research is empty and the scan continues.
- The report gets a **Research** section, for example
  `CVE-XXXX-YYYY (CVSS 9.8, KEV) score 0.90 → tested: version-fingerprint: VERIFIED — …`.

| Flag | Description |
|------|-------------|
| `--research on\|off` | Known-CVE research (default `on`) |
| `--research-cache-ttl N` | Research cache TTL in seconds (default 86400) |

Defaults can be set in `~/.config/suvari/config.json`:

```json
{"research": {"enabled": true, "sources": ["nvd", "kev"], "max_results": 20, "cache_ttl": 86400}}
```

`sources` may also include `"ghsa"`.

### Hosts, services and the local machine

A bare IP, hostname, CIDR or range is a **host target**: Suvari port-scans it
first (plain TCP connect, no nmap needed), reads each port's banner, names the
service, and then runs read-only protocol checks. Each HTTP(S) port it finds
becomes its own web target, scanned by the normal web loop. URLs stay web
targets. `host:port` scans only that port.

```bash
python suvari.py auto --target 10.0.0.5                     # top-100 ports + web
python suvari.py auto --target 127.0.0.1 --ports 8000-9100 --no-web
python suvari.py auto --target 192.168.1.0/24 --ports 22,80,443,6379 --rate 6000
python suvari.py auto --local                               # audit this machine only
```

- **Service checks** (one attempt each, 3 s timeout, no password guessing, no
  write commands; every payload passes a read-only guard): Redis `PING`,
  memcached `stats`, MongoDB `isMaster` + `listDatabases nameOnly`,
  Elasticsearch `GET /` and `/_cat/indices`, Docker API `GET /version` and
  `/containers/json`, anonymous FTP login (no listing), SMTP `EHLO` (STARTTLS
  only, no relay test), SSH server KEXINIT (weak algorithms), DNS `AXFR`
  (hostname targets only), SMB null session (if `smbclient` is installed), VNC
  security types, and TLS certificate expiry and TLS 1.0/1.1 acceptance. Only
  counts and versions are recorded, never keys, documents or share names.
- **Prior:** 0.5 for a check on an identified service, 0.3 for an unidentified
  open port (its `svc-identify` check spawns the right checks once the
  service is named).
- **Rate:** every port-scan connect counts toward `--rate` and
  `--max-requests`. A 1 000-port scan at the default 60/min takes about 17 min,
  so raise `--rate` for wide scans of hosts you own.
- **Local audit** (`--local`, read-only): listening sockets with their owning
  processes, `sshd` settings (`sshd -T` when available), world-writable
  critical paths, SUID/SGID binaries, `docker.sock` permissions, cron, `~/.ssh`
  permissions, and UID 0 accounts or accounts with empty passwords.
- The report gets **Host profile**, **Service findings** and **Local audit**
  sections, and the summary adds counts of open ports and of service, web and
  local findings.

| Flag | Description |
|------|-------------|
| `--ports SPEC` | `top100` (default), `all`, `1-1024`, `22,80,8000-8100` |
| `--udp` | Also probe UDP 53/123/161 (DNS `version.bind`, NTP time request, SNMPv3 engine discovery; no community strings) |
| `--no-web` | Do not web-scan HTTP(S) ports found by discovery |
| `--no-discovery` | Old behaviour: a bare IP/host is a web target on port 80 |
| `--local` | Read-only audit of this machine; works without a target |

## `bb` — Bug Bounty Recon

```bash
python suvari.py bb https://example.com
```

Focused bug bounty workflow:
- Subdomain enumeration (subfinder, dnsenum)
- URL discovery (gau, waybackurls)
- Parameter discovery (arjun)
- Technology fingerprinting (httpx, wafw00f)

## `chat` — Interactive Pentesting Chat

```bash
python suvari.py chat
```

Natural conversation mode. Supports both security testing and CTF challenges:

```
You > scan https://example.com
You > check /api/users on that site
You > I have a pcap file with DNS exfiltration
You > binary with buffer overflow, need to find the flag
You > try SQL injection on the search parameter
```

### Chat Commands

| Command | Description |
|---------|-------------|
| `scan <url>` | Run full scan |
| `scan <url> -s` | Server scan |
| `recon <url>` | Quick recon |
| `check <path>` | Check specific endpoint |
| `report` | Show last scan report |
| `history` | List previous scans |
| `help` | Show available commands |
| `exit` | Quit chat |

## `report` — Show Scan Report

```bash
python suvari.py report ./output/20260101_120000_example_com/
```

## `list` — List Previous Scans

```bash
python suvari.py list
```

## `configure` — Interactive Setup

```bash
python suvari.py configure
```

Prompts for provider, model, and API key. Config saved to `~/.config/suvari/`.

## `help` — Command Reference

```bash
python suvari.py help
```
