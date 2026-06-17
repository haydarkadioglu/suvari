# Suvari

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
- **Multi-LLM** — OpenAI, Anthropic, DeepSeek, Gemini, OpenRouter, Ollama
- **Server scan** (`-s`) — full port scan + service detection, SSH/FTP/SMB/DB checks
- **White-box** (`-r`) — source code analysis alongside live testing
- **Chat mode** — interactive conversation + CTF challenge solving
- **MCP server** — compatible with Claude Desktop, Cursor, VS Code Copilot
- **Failure recovery** — L0-L5 failure attribution, automatic tool fallbacks
- **Bug bounty workflow** — subdomain/URL/parameter discovery
- **No Docker required** — uses existing Kali tools directly

## Documentation

Full documentation: [DOCS.md](DOCS.md)

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
│   ├── agents/ (recon, scanner, analyzer, exploiter, bugbounty)
│   ├── tools/runner.py     # Subprocess + caching
│   └── prompts/            # Jinja2 templates
└── requirements.txt
```

Inspired by [Shannon](https://github.com/KeygraphHQ/shannon), [PentAGI](https://github.com/vxcontrol/pentagi), [LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent), and [HexStrike AI](https://github.com/0x4m4/hexstrike-ai).
