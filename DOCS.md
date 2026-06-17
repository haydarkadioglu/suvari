# Suvari Documentation

## Installation

```bash
git clone https://github.com/haydarkadioglu/suvari.git
cd suvari
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python suvari.py configure   # One-time setup
```

## CLI Commands

### `scan` — Full Security Scan (default: tree-based)

```bash
python suvari.py scan https://example.com

# Options:
  -f, --fast          Fast mode (fewer tests, quicker results)
  -s, --server        Full server scan (SSH, FTP, SMB, DB, all ports)
  -r, --source PATH   White-box mode (include source code analysis)
  -P, --parallel INT  Parallel tool count (default: 3)
  -M, --mode MODE     auto | guided | interactive
  -p, --provider      openai | anthropic | deepseek | gemini | openrouter | ollama
  -m, --model NAME    Specific model name (e.g. gpt-4o, deepseek-chat)
  -v, --verbose       Verbose output
```

The scan runs as a **decision tree**: after each tool, the AI evaluates results and decides what to try next. If something interesting is found, it drills deeper. If a tool fails, it tries an alternative.

### `recon` — Quick Reconnaissance

```bash
python suvari.py recon https://example.com
```

Runs whatweb, nmap, curl headers, and common path checks in parallel. Returns technology stack, open ports, and basic exposure.

### `attack` — Exploit Previous Findings

```bash
python suvari.py attack ./output/20260101_120000_example_com/
```

Reads the findings from a previous scan and runs targeted exploitation (sqlmap, hydra, etc.) based on what was found.

### `bb` — Bug Bounty Recon

```bash
python suvari.py bb https://example.com
```

Focused bug bounty workflow: subdomain enumeration, URL discovery (gau, waybackurls), parameter discovery (arjun), and technology fingerprinting.

### `chat` — Interactive Pentesting Chat

```bash
python suvari.py chat
```

Natural conversation mode. Works for both security testing and CTF challenges:

```
You > scan https://example.com
You > check /api/users on that site
You > I have a pcap file with DNS exfiltration
You > binary with buffer overflow, need to find the flag
```

### `report` — Show Previous Report

```bash
python suvari.py report ./output/20260101_120000_example_com/
```

### `list` — List Previous Scans

```bash
python suvari.py list
```

### `configure` — Interactive Setup

```bash
python suvari.py configure
```

Prompts for provider (OpenAI, Anthropic, DeepSeek, Gemini, OpenRouter, Ollama), model, and API key. Config saved to `~/.config/suvari/`.

## MCP Server

Suvari can run as an MCP (Model Context Protocol) server, compatible with Claude Desktop, Cursor, VS Code Copilot, and any MCP client.

### Start the MCP Server

```bash
python suvari_mcp.py
```

The server listens on stdio (default MCP transport) and exposes 6 tools:

| Tool | Description |
|------|-------------|
| `scan_target(url, fast, server)` | Full security scan |
| `recon_target(url)` | Quick reconnaissance |
| `run_tool(tool, target, args)` | Run specific security tool |
| `list_available_tools()` | List all available Kali tools |
| `get_scan_report(scan_dir)` | Read scan report |
| `analyze_ctf(description)` | Analyze CTF challenge |

### Claude Desktop Integration

Add to `~/.config/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "suvari": {
      "command": "python3",
      "args": ["/path/to/suvari/suvari_mcp.py"]
    }
  }
}
```

### Cursor / VS Code Integration

Copy `suvari-mcp.json` to `.vscode/mcp.json` in your project.

## Supported Providers

| Provider | Env Variable | Default Model |
|----------|-------------|---------------|
| OpenAI | `OPENAI_API_KEY` | gpt-4o |
| Anthropic | `ANTHROPIC_API_KEY` | claude-sonnet-4 |
| DeepSeek | `DEEPSEEK_API_KEY` | deepseek-chat |
| Gemini | `GEMINI_API_KEY` | gemini-2.5-flash |
| OpenRouter | `OPENROUTER_API_KEY` | openai/gpt-4o |
| Ollama | (local) | llama3 |

## Scan Modes

| Mode | Flag | Behavior |
|------|------|----------|
| Guided (default) | *(none)* | AI decides next steps, shows findings live |
| Auto | `-M auto` | Fully automated, no questions, minimal output |
| Interactive | `-M interactive` | Full user control, confirms each action |

## Architecture

```
suvari/
├── suvari.py               # CLI entry point
├── suvari_mcp.py           # MCP server entry point
├── suvari/
│   ├── cli.py              # Command definitions
│   ├── chat.py             # Interactive chat + CTF support
│   ├── mcp_server.py       # MCP tool definitions
│   ├── llm.py              # Multi-provider LLM client
│   ├── orchestrator.py     # Pipeline controller with tree scan
│   ├── chain.py            # Tree-based recursive scanning
│   ├── core.py             # Planner-Executor-Reflector
│   ├── failure.py          # L0-L5 failure attribution
│   ├── knowledge.py        # Knowledge graph
│   ├── state.py            # Checkpoint/resume
│   ├── mode.py             # Scan modes
│   ├── config.py           # Interactive config wizard
│   ├── report.py           # Report generator
│   ├── workspace.py        # Output management
│   ├── scan_logger.py      # JSON logging
│   ├── prompt_loader.py    # Jinja2 prompt loader
│   ├── tools/runner.py     # Subprocess wrapper + caching
│   ├── agents/
│   │   ├── recon.py        # Parallel reconnaissance
│   │   ├── scanner.py      # AI-driven scanning
│   │   ├── analyzer.py     # LLM vulnerability analysis
│   │   ├── exploiter.py    # Proof-of-concept exploits
│   │   └── bugbounty.py    # Bug bounty workflow
│   └── prompts/            # Phase-specific prompt templates
│       ├── shared/
│       ├── recon/
│       ├── scanner/
│       ├── analyzer/
│       └── exploiter/
└── requirements.txt
```

## Dependencies

- Python 3.10+
- Kali Linux (or any Linux with security tools)
- No Docker required (optional for vulnerable test targets)
- Internet access for LLM API calls
