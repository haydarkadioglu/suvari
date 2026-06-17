# Suvari 🐎

AI-powered black-box web + server pentester. Chat with it, scan with it, hack with it.

## Features

- **💬 Chat mode** — `python suvari.py chat` opens an interactive pentesting conversation. Talk naturally: "scan this", "check /api", "try SQL injection"
- **🖥️ Server scan** (`-s`) — full port scan + service detection, checks SSH/FTP/SMB/DB
- **🤖 AI-driven** — LLM (OpenAI/Anthropic/DeepSeek/Gemini/OpenRouter/Ollama) plans tool selection
- **💡 Interactive guidance** — give hints during scan: "check /api for IDOR", "look for JWT tokens"
- **🐳 No Docker required** — uses existing Kali tools directly
- **📋 Multi-phase pipeline**: Recon → Scan → AI Analysis → Exploit → Report
- **🔄 Resumable** — partial outputs remain, continue from where you left off
- **⚙️ 3 scan modes**: auto, guided (default), interactive
- **📁 White-box mode** (`-r`) — include source code in analysis
- **📝 Scan logging** — every scan writes structured logs to `scan.log`

## Quick Start

```bash
pip install -r requirements.txt
python suvari.py configure          # One-time setup (provider + API key)

# 💬 Chat mode (interactive conversation)
python suvari.py chat

# 🌐 Web app scan
python suvari.py scan https://example.com

# 🖥️ Full server scan (all ports + services)
python suvari.py scan https://server.com -s

# 📁 White-box mode (with source code)
python suvari.py scan https://example.com -r /path/to/source

# ⚡ Fast mode
python suvari.py scan https://example.com --fast
```

## 💬 Chat Mode

The chat mode lets you interact with Suvari like a security expert:

```
$ python suvari.py chat

You > scan https://juice-shop.herokuapp.com
  🔍 Scanning... found 5 vulnerabilities!
  🔥 [CRITICAL] SQL Injection — /rest/products/search?q=
  ⚠️ [HIGH] IDOR — /api/users

You > check /api/users on that
  Checking /api/users...

You > what else should I look for?
  (Suvari suggests next steps based on context)

You > exit
```

## Scan Modes

| Mode | Flag | Behavior |
|------|------|----------|
| **Guided** (default) | *(none)* | Asks for suggestions, OK for slow tools, shows findings live |
| **Auto** | `-M auto` | Fully automated, no questions, minimal output. CI/CD ready |
| **Interactive** | `-M interactive` | Chat-like, asks before each tool, full user control |

## Example Chat Session

```bash
python suvari.py chat

# Inside chat:
scan https://example.com --fast
scan https://example.com -s          # server scan
scan https://example.com -r ./src    # white-box
recon https://example.com            # recon only
check /api                           # quick endpoint check
report                               # show last report
history                              # list past scans
help                                 # show commands
```

## Configuration

```bash
python suvari.py configure
```

Supported providers: OpenAI, Anthropic (Claude), **DeepSeek**, Google Gemini, OpenRouter, Ollama (local).

Config saved to `~/.config/suvari/`.

## Architecture

```
suvari/
├── suvari.py               # Entry point
├── suvari/
│   ├── cli.py              # Typer CLI (scan, recon, chat, configure, report, list)
│   ├── chat.py             # Interactive chat session
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
