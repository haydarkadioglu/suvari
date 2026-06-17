# Architecture

## Overview

Suvari uses a multi-agent pipeline with tree-based scanning. Each phase feeds into the next, and the AI decides the next steps dynamically.

```
Input: URL
  │
  ├── Browser Agent (always runs)
  │   ├── Page render + SPA detection
  │   ├── Login form detection
  │   │   ├── Default credentials test
  │   │   ├── Self-registration (if no creds)
  │   │   └── Provided credentials (--login)
  │   ├── DOM XSS check
  │   └── Screenshot evidence
  │
  ├── Recon Agent (parallel)
  │   ├── whatweb — technology fingerprinting
  │   ├── nmap — port scanning
  │   ├── curl — headers, robots.txt, paths
  │   └── Source code (white-box mode)
  │
  ├── Scanner (tree-based chain)
  │   ├── AI plans tool selection
  │   ├── Parallel execution with fallbacks
  │   ├── Failure attribution (L0-L5)
  │   └── Drills deeper on findings
  │
  ├── CVE Intelligence
  │   ├── Version extraction from recon
  │   ├── CVE database lookup
  │   ├── searchsploit fallback
  │   └── AI exploit generation
  │
  ├── JWT Analysis
  │   ├── Token extraction
  │   ├── Decode + algorithm detection
  │   ├── Weak secret brute force
  │   └── Algorithm confusion test
  │
  ├── Analyzer (AI)
  │   └── LLM vulnerability classification
  │
  ├── Exploiter
  │   └── Proof-of-concept exploitation
  │
  └── Report
      └── Markdown report with findings
```

## Directory Structure

```
suvari/
├── suvari.py               # CLI entry point
├── suvari_mcp.py           # MCP server entry point
├── suvari-mcp.json         # MCP config for Claude/Cursor
├── requirements.txt
├── README.md
├── docs/                   # Documentation
│   ├── index.md
│   ├── installation.md
│   ├── commands.md
│   ├── mcp.md
│   └── architecture.md
└── suvari/
    ├── __init__.py
    ├── cli.py              # Command definitions
    ├── chat.py             # Interactive chat + CTF
    ├── mcp_server.py       # MCP tool definitions
    ├── llm.py              # Multi-provider LLM client
    ├── orchestrator.py     # Pipeline controller
    ├── chain.py            # Tree-based recursive scan
    ├── core.py             # Planner-Executor-Reflector
    ├── failure.py          # L0-L5 failure attribution
    ├── knowledge.py        # Knowledge graph
    ├── state.py            # Checkpoint/resume
    ├── mode.py             # Scan modes
    ├── config.py           # Interactive config wizard
    ├── report.py           # Markdown report generator
    ├── workspace.py        # Output management
    ├── scan_logger.py      # JSON logging
    ├── prompt_loader.py    # Jinja2 prompt loader
    ├── browser.py          # Browser automation (Playwright)
    ├── cve_intel.py        # CVE lookup + exploit generation
    ├── jwt_analysis.py     # JWT token analysis
    ├── tools/
    │   ├── __init__.py
    │   └── runner.py       # Subprocess + caching + ANSI cleanup
    ├── agents/
    │   ├── __init__.py
    │   ├── base.py         # Base agent class
    │   ├── recon.py        # Parallel reconnaissance
    │   ├── scanner.py      # AI-driven scanning with fallbacks
    │   ├── analyzer.py     # LLM vulnerability analysis
    │   ├── exploiter.py    # Proof-of-concept exploits
    │   └── bugbounty.py    # Bug bounty workflow
    └── prompts/            # Jinja2 prompt templates
        ├── shared/         # Shared fragments
        ├── recon/
        ├── scanner/
        ├── analyzer/
        └── exploiter/
```

## Agent System

| Agent | Function | AI-driven |
|-------|----------|-----------|
| Browser | Page render, login, DOM XSS | No (headless Chrome) |
| Recon | Technology, ports, headers | No (parallel tools) |
| Scanner | Tool selection + execution | Yes (AI plans tools) |
| CVE Intel | Version → CVE lookup | Partial (LLM for exploit gen) |
| JWT | Token decode + attack | No (algorithmic) |
| Analyzer | Vulnerability classification | Yes (LLM analysis) |
| Exploiter | Proof-of-concept | Yes (LLM suggests payloads) |

## Key Design Decisions

- **No Docker** — uses existing Kali tools directly via subprocess
- **Tree-based scanning** — AI decides next steps based on findings
- **Failure recovery** — L0-L5 classification with automatic fallback tools
- **Result caching** — same cmd+target returns cached results (max 100)
- **Checkpoint/resume** — scan state saved after each phase
- **Multi-LLM** — OpenAI, Anthropic, DeepSeek, Gemini, OpenRouter, Ollama
- **MCP support** — expose all tools via Model Context Protocol
