# Suvari 🐎

AI-powered black-box web + server pentester. Give the URL, Suvari handles the rest.

## Features

- **Black-box** — no source code needed, just a URL or IP
- **Server scan** (`-s`) — full port scan + service detection, checks SSH/FTP/SMB/DB
- **AI-driven** — LLM (OpenAI/Anthropic/DeepSeek/Gemini/OpenRouter/Ollama) plans tool selection
- **Interactive guidance** — user can give hints during scan ("check /api", "try SQLi on login")
- **No Docker required** — uses existing Kali tools directly
- **Multi-phase pipeline**: Recon → Scan → AI Analysis → Exploit → Report
- **Resumable** — partial outputs remain, continue from where you left off
- **3 scan modes**: auto, guided (default), interactive
- **White-box mode** (`-r`) — include source code in analysis

## Quick Start

```bash
pip install -r requirements.txt
python suvari.py configure          # One-time setup (provider + API key)

# Web app scan
python suvari.py scan https://example.com

# Full server scan (all ports + services)
python suvari.py scan https://server.com -s

# Interactive mode (ask before each tool)
python suvari.py scan https://example.com -M interactive

# Fast mode
python suvari.py scan https://example.com --fast

# White-box mode (with source code)
python suvari.py scan https://example.com -r /path/to/source
```

## Scan Modes

| Mode | Flag | Behavior |
|------|------|----------|
| **Guided** (default) | *(none)* | Asks for suggestions, OK for slow tools, shows findings live |
| **Auto** | `-M auto` | Fully automated, no questions, minimal output. CI/CD ready |
| **Interactive** | `-M interactive` | Asks before EVERY tool, full user control |

## Configuration

```bash
python suvari.py configure
```

Supported providers: OpenAI, Anthropic (Claude), DeepSeek, Google Gemini, OpenRouter, Ollama (local).

Config saved to `~/.config/suvari/`.

## Example Scan

```bash
# Web server
python suvari.py scan https://juice-shop.herokuapp.com

# During scan, user can suggest:
# → check /api for IDOR
# → try SQL injection on search
# → look for JWT tokens
```

## Architecture

```
suvari/
├── suvari.py               # Entry point
├── suvari/
│   ├── cli.py              # Typer CLI
│   ├── llm.py              # Multi-provider LLM client
│   ├── config.py           # Interactive config wizard
│   ├── orchestrator.py     # Pipeline controller
│   ├── core.py             # P-E-R framework (Planner, Reflector)
│   ├── state.py            # Checkpoint/resume
│   ├── knowledge.py        # Knowledge graph + failure attribution
│   ├── prompt_loader.py    # Jinja2 prompt loader
│   ├── scan_logger.py      # File logging
│   ├── mode.py             # Scan modes + suggestion system
│   ├── report.py           # Markdown report generator
│   ├── workspace.py        # Output directory management
│   ├── agents/
│   │   ├── recon.py        # Reconnaissance
│   │   ├── scanner.py      # AI-driven tool selection
│   │   ├── analyzer.py     # LLM vulnerability analysis
│   │   └── exploiter.py    # Proof-of-concept exploits
│   ├── tools/
│   │   └── runner.py       # Kali tool subprocess wrapper
│   └── prompts/            # Shannon-inspired prompt templates
│       ├── shared/
│       ├── recon/
│       ├── scanner/
│       ├── analyzer/
│       └── exploiter/
└── requirements.txt
```

Inspired by [Shannon](https://github.com/KeygraphHQ/shannon), [PentAGI](https://github.com/vxcontrol/pentagi), and [LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent).
