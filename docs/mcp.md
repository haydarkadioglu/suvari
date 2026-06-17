# MCP Server

Suvari can run as an MCP (Model Context Protocol) server, exposing its security tools to any MCP-compatible AI client: Claude Desktop, Cursor, VS Code Copilot, and others.

## Quick Start

```bash
cd ~/Desktop/suvari
source .venv/bin/activate
python suvari_mcp.py
```

The server starts and listens on **stdio** (standard MCP transport). It exposes 6 tools:

| Tool | Description |
|------|-------------|
| `scan_target` | Full security scan with browser, CVE intel, JWT analysis |
| `recon_target` | Quick reconnaissance (ports, tech, headers) |
| `run_tool` | Execute a specific Kali tool |
| `list_available_tools` | List all installed security tools |
| `get_scan_report` | Read a previous scan report |
| `analyze_ctf` | Analyze a CTF challenge by description |

## Claude Desktop Integration

Add to your Claude Desktop config file:

**Linux:** `~/.config/Claude/claude_desktop_config.json`
**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "suvari": {
      "command": "python3",
      "args": ["/home/kali/Desktop/suvari/suvari_mcp.py"],
      "description": "Suvari — AI-powered web and server pentester",
      "timeout": 300,
      "disabled": false
    }
  }
}
```

Restart Claude Desktop. You can now say:

```
"Scan https://example.com for vulnerabilities"
"Run nmap on that host"
"What tools do you have installed?"
```

## Cursor Integration

1. Copy `suvari-mcp.json` to `.cursor/mcp.json` in your project:

```bash
cp suvari-mcp.json .cursor/mcp.json
```

2. Restart Cursor. Suvari tools will appear in the MCP tool list.

## VS Code Copilot Integration

1. Create `.vscode/mcp.json` in your project:

```json
{
  "servers": {
    "suvari": {
      "type": "stdio",
      "command": "python3",
      "args": ["/path/to/suvari/suvari_mcp.py"]
    }
  }
}
```

2. Reload VS Code window. Suvari tools are now available to Copilot.

## Using the Tools

Once connected, your AI client can call the tools:

### scan_target

```
Purpose: Run full security scan
Parameters:
  url (required): Target URL
  fast (optional): Boolean, fast mode
  server (optional): Boolean, scan all ports/services
```

Example from Claude:

```
User: "Check the security of https://example.com"
Claude: I'll run a full scan.
[Calling scan_target(url="https://example.com")]
Scan complete. Found 3 vulnerabilities:
- [HIGH] SQL Injection at /search?q=
- [MEDIUM] Missing security headers
- [LOW] Server version disclosure
```

### analyze_ctf

```
Purpose: Analyze CTF challenges
Parameters:
  description (required): Natural language description
```

Example:

```
User: "I have a pcap with DNS exfiltration"
Claude: [Calling analyze_ctf(description="pcap with DNS exfiltration")]
Check DNS query names in the pcap file. Each subdomain may contain
base64-encoded data. Use: tshark -r capture.pcap -Y "dns" -T fields
-e dns.qry.name | sort -u | grep -v "\.$"
```

## Running as HTTP Server (Advanced)

The MCP server can also run over HTTP instead of stdio:

```python
# Add this to suvari_mcp.py or create a custom wrapper
from suvari.mcp_server import mcp
mcp.run(transport="sse", port=8888)
```

This allows remote AI clients to connect via HTTP.
