# Suvari 🐎

AI-powered black-box web pentester. Give the URL, Suvari handles the rest.

## Features

- **Black-box** — no source code needed, just a URL
- **AI-powered** — LLM (OpenAI/Anthropic/DeepSeek/Gemini/OpenRouter/Ollama) drives intelligent analysis
- **No Docker required** — uses existing Kali tools directly
- **Multi-phase pipeline**: Recon → Scan → AI Analysis → Exploit → Report
- **Resumable** — partial outputs remain in the workspace directory
- **Interactive config** — `python suvari.py configure` sets everything up

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Interactive setup (provider + API key)
python suvari.py configure

# Run a scan
python suvari.py scan https://example.com

# Fast mode (fewer tests)
python suvari.py scan https://example.com --fast

# Specific provider
python suvari.py scan https://example.com -p deepseek -m deepseek-chat
```

## Configuration

```bash
python suvari.py configure
```

This interactive wizard lets you pick:

| # | Provider | API Key Env |
|---|----------|-------------|
| 1 | OpenAI | `OPENAI_API_KEY` |
| 2 | Anthropic (Claude) | `ANTHROPIC_API_KEY` |
| 3 | DeepSeek | `DEEPSEEK_API_KEY` |
| 4 | Google Gemini | `GEMINI_API_KEY` |
| 5 | OpenRouter | `OPENROUTER_API_KEY` |
| 6 | Ollama (local) | none needed |

Config is saved to `~/.config/suvari/` — after that, just run `scan` without flags.

## Output

```
output/
└── 20250220_143020_example_com/
    ├── meta.json
    ├── recon/
    │   ├── whatweb.txt
    │   ├── headers.txt
    │   ├── nmap.txt
    │   └── robots.txt
    ├── scans/
    │   ├── nuclei.txt
    │   └── nikto.txt
    ├── analysis/
    │   └── findings.json
    ├── exploit/
    │   └── results.json
    └── report.md
```

## Architecture

```
suvari/
├── suvari.py               # Entry point
├── suvari/
│   ├── cli.py              # Typer CLI (scan/recon/report/list/configure)
│   ├── llm.py              # Multi-provider LLM client
│   ├── config.py           # Interactive configuration wizard
│   ├── workspace.py        # Output directory management
│   ├── orchestrator.py     # Pipeline controller
│   ├── report.py           # Markdown report generator
│   ├── agents/
│   │   ├── base.py         # Abstract base agent
│   │   ├── recon.py        # Reconnaissance (whatweb, nmap, curl)
│   │   ├── scanner.py      # Vulnerability scanning (AI-driven tool selection)
│   │   ├── analyzer.py     # AI analysis (LLM-powered findings)
│   │   └── exploiter.py    # Proof-of-concept exploitation (sqlmap, curl)
│   └── tools/
│       └── runner.py       # Kali tool subprocess wrapper
└── requirements.txt
```

Inspired by [Shannon](https://github.com/KeygraphHQ/shannon), [PentAGI](https://github.com/vxcontrol/pentagi), and [LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent).
