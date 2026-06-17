# Suvari

> **DISCLAIMER:** Suvari is a security testing tool designed for authorized penetration testing and educational purposes only. You must have explicit written permission from the target owner before scanning any system. Unauthorized use of this tool against systems you do not own or have permission to test is illegal. The authors assume no liability and are not responsible for any misuse or damage caused by this program. By using this software, you agree to use it responsibly and in compliance with all applicable laws.

AI-powered black-box web + server pentester with MCP support.

## Quick Start

```bash
pip install -r requirements.txt
python suvari.py configure          # One-time setup
python suvari.py scan https://example.com
```

## Features

- **Tree-based scanning** — AI decides next steps, drills deeper on findings, fallback tools on failure
- **27+ Kali tools** — nmap, nuclei, gobuster, ffuf, sqlmap, hydra, enum4linux, etc.
- **Browser agent** — login, default creds, self-registration, DOM XSS, screenshots
- **CVE intelligence** — version-based CVE lookup + AI exploit generation
- **JWT analysis** — decode, algorithm confusion, weak secret brute force
- **Multi-LLM** — OpenAI, Anthropic, DeepSeek, Gemini, OpenRouter, Ollama
- **Server scan** (`-s`) — full port scan + service detection, SSH/FTP/SMB/DB checks
- **White-box** (`-r`) — source code analysis alongside live testing
- **Chat mode** — interactive conversation + CTF challenge solving
- **MCP server** — compatible with Claude Desktop, Cursor, VS Code Copilot
- **Failure recovery** — L0-L5 failure attribution, automatic tool fallbacks
- **Bug bounty workflow** — subdomain/URL/parameter discovery
- **No Docker required** — uses existing Kali tools directly

## Documentation

Documentation: [docs/index.md](docs/index.md) — installation, commands, MCP setup, architecture.

## Commands

```
configure   Interactive setup
scan        Full scan (tree-based, default mode)
recon       Quick reconnaissance
attack      Exploit previous scan findings
bb          Bug bounty workflow
chat        Interactive chat + CTF
report      Show previous report
list        List past scans
```

## MCP Server

```bash
python suvari_mcp.py
```

Exposes 6 tools for Claude Desktop, Cursor, Copilot: scan_target, recon_target, run_tool, list_available_tools, get_scan_report, analyze_ctf.

## Architecture

```
suvari/
├── suvari.py               # CLI
├── suvari_mcp.py           # MCP server
├── suvari/
│   ├── cli.py / chat.py / mcp_server.py
│   ├── llm.py / orchestrator.py / chain.py
│   ├── failure.py / knowledge.py / state.py
│   ├── browser.py          # Playwright automation
│   ├── cve_intel.py        # CVE + exploit generation
│   ├── jwt_analysis.py     # JWT analysis
│   ├── agents/ (recon, scanner, analyzer, exploiter, bugbounty)
│   ├── tools/runner.py     # Subprocess + caching
│   └── prompts/            # Jinja2 templates
└── requirements.txt
```

Inspired by [Shannon](https://github.com/KeygraphHQ/shannon), [PentAGI](https://github.com/vxcontrol/pentagi), [LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent), and [HexStrike AI](https://github.com/0x4m4/hexstrike-ai).

## License

[MIT](LICENSE)
