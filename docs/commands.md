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
