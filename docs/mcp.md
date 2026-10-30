# Suvari MCP Server

Suvari exposes 75+ Kali Linux tools as MCP (Model Context Protocol) tools.
AI agents (Claude, Cursor, Copilot, custom) can connect and use any Kali tool.

## Quick Start

```bash
# Default (streamable-http on 127.0.0.1:8000)
python suvari_mcp.py

# Custom port
python suvari_mcp.py --port 8080

# SSE transport
python suvari_mcp.py --sse
```

The bind address and port can also be set with the `MCP_HOST` and `MCP_PORT`
environment variables. Command-line flags take precedence.

### Network access (discouraged)

> **Warning:** the server has **no authentication**. Anyone who can reach the
> port can run every tool on this machine, which is remote code execution by
> design. Keep the default loopback bind unless the network is fully trusted.

Binding to anything other than loopback must be requested explicitly, and the
server logs a warning at startup:

```bash
# Discouraged: reachable from the network, no authentication
python suvari_mcp.py --host 10.1.2.3
python suvari_mcp.py --host 0.0.0.0
```

DNS-rebinding protection stays on, so requests are only accepted if their
`Host` header is a loopback name or the exact `--host` value. Clients must
connect to `http://10.1.2.3:8000/mcp` in the first example. With
`--host 0.0.0.0` a client that connects through a real IP or hostname gets
`421 Invalid Host header`, so prefer binding the specific address.

Tunnels such as ngrok send their public hostname as `Host`. Keep the loopback
bind and have the tunnel rewrite the header:

```bash
python suvari_mcp.py
ngrok http 8000 --host-header=localhost:8000
```

A tunnel publishes the unauthenticated server to the internet, so the warning
above applies in full.

## Transport Formats

| Transport | Endpoint | Clients |
|-----------|----------|---------|
| streamable-http (default) | `POST /mcp` | Claude Desktop, Cursor, Copilot |
| SSE | `GET /sse` + `POST /messages` | Claude Desktop (older), custom |
| JSON-RPC over HTTP | `POST /mcp` | Any HTTP client (curl, Python) |

## Connection Examples

### Python (requests)
```python
import requests
s = requests.Session()
url = "http://localhost:8000/mcp"

# Initialize
r = s.post(url, json={"jsonrpc":"2.0","method":"initialize",
    "params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}},
    "id":1})
sid = r.json().get("sessionId", "")

# List tools
r = s.post(url, json={"jsonrpc":"2.0","method":"tools/list","id":2},
    headers={"Mcp-Session-Id": sid} if sid else {})
print(r.json())

# Call tool
r = s.post(url, json={"jsonrpc":"2.0","method":"tools/call",
    "params":{"name":"nmap","arguments":{"target":"scanme.nmap.org","args":"-F"}},
    "id":3},
    headers={"Mcp-Session-Id": sid} if sid else {})
print(r.json()["content"][0]["text"][:500])
```

### curl
```bash
# Initialize
curl -s -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl","version":"1"}},"id":1}'

# Tools list (with session ID from initialize response)
curl -s -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <session_id>" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":2}'

# Run nmap
curl -s -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <session_id>" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"nmap","arguments":{"target":"scanme.nmap.org","args":"-F"}},"id":3}'
```

## Available Tools

All installed Kali tools are available automatically:
`nmap`, `nuclei`, `gobuster`, `ffuf`, `sqlmap`, `hydra`, `whatweb`, `nikto`, `wpscan`, `masscan`, `curl`, `dig`, `dnsenum`, `dnsrecon`, `enum4linux`, `smbmap`, etc.

Run `python -c "from suvari.mcp_server import _get_runner; r=_get_runner(); print('\n'.join(sorted(r.available_tools())))"` for full list.

## Config for AI Clients

### LM Studio
```json
{
  "mcpServers": {
    "suvari": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

### Claude Desktop
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

### Cursor / VS Code Copilot
Uses stdio transport. Same as Claude Desktop config above.
