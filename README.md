```
 ____                        _ 
/ ___| _   ___   ____ _ _ __(_)
\___ \| | | \ \ / / _` | '__| |
 ___) | |_| |\ V / (_| | |  | |
|____/ \__,_| \_/ \__,_|_|  |_|
```

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tools](https://img.shields.io/badge/Tools-68%20Kali-brightgreen.svg)](https://github.com/haydarkadioglu/suvari)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://github.com/haydarkadioglu/suvari)
[![Agent](https://img.shields.io/badge/AI%20Agents-5%2B-purple.svg)](https://github.com/haydarkadioglu/suvari)
[![Scan](https://img.shields.io/badge/Scan-Causal%20Chain-orange.svg)](https://github.com/haydarkadioglu/suvari)
[![Stars](https://img.shields.io/github/stars/haydarkadioglu/suvari?style=social)](https://github.com/haydarkadioglu/suvari)

# **Suvari** — AI-Powered Black-Box **Web & Server Pentester**
68 Kali tools • MCP support • Multi-LLM • Causal chain scanning.

> **DISCLAIMER:** For authorized testing only. Unauthorized use is illegal. By using this software you agree to use it responsibly.

## Quick Start

```bash
pip install -r requirements.txt
python suvari.py configure
python suvari.py scan https://example.com
```

## Features

- **68 Kali tools** — nmap, nuclei, sqlmap, hydra, gobuster, masscan, impacket, searchsploit, msfvenom...
- **Causal chain scanning** — each step feeds into the next, AI decides adaptively
- **P-E-R chat** — AI plans, executes tools, reflects on results
- **Browser agent** — login, DOM XSS, self-registration, screenshots
- **Attack chains** — connects findings into exploit chains
- **Agent delegation** — scanner spawns exploiters for each finding
- **CVE intelligence** — version-based lookup + exploit generation
- **JWT analysis** — decode, algorithm confusion, brute force
- **Failure recovery** — L0-L5 classification, automatic fallback tools
- **Multi-LLM** — OpenAI, Anthropic, DeepSeek, Gemini, OpenRouter, Ollama
- **MCP server** — Claude Desktop, Cursor, VS Code Copilot
- **Bug bounty** — subdomain/URL/parameter discovery

## Commands

```
configure   Setup provider, model, API key
scan        Full smart scan (3-phase adaptive)
recon       Quick reconnaissance
attack      P-E-R exploitation of previous findings
bb          Bug bounty recon
chat        Interactive chat + CTF
report      Show report
list        Past scans
```

## MCP

```bash
python suvari_mcp.py
```
Tools: scan_target, recon_target, run_tool, list_available_tools, get_scan_report, analyze_ctf.

## Quick Links

- [Installation](docs/installation.md)
- [Commands](docs/commands.md)
- [MCP Setup](docs/mcp.md)
- [Architecture](docs/architecture.md)
- [Providers](docs/providers.md)

Inspired by [Shannon](https://github.com/KeygraphHQ/shannon), [PentAGI](https://github.com/vxcontrol/pentagi), [LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent), [HexStrike AI](https://github.com/0x4m4/hexstrike-ai).

## License

[MIT](LICENSE)
