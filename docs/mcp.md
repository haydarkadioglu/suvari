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

## Authentication

The server uses a static bearer token. Set it with `SUVARI_MCP_TOKEN` or
`--token`; if both are set, `--token` wins:

```bash
export SUVARI_MCP_TOKEN="$(openssl rand -hex 32)"
python suvari_mcp.py

# Same effect, but the token is visible in the process list
python suvari_mcp.py --token "$SUVARI_MCP_TOKEN"
```

With a token configured, every HTTP request must carry
`Authorization: Bearer <token>`. Anything else gets `401` with
`WWW-Authenticate: Bearer realm="suvari"` and this body:

```json
{"error": "unauthorized", "detail": "missing or invalid bearer token"}
```

Rejected requests are logged at `WARNING` with the client address. The presented
token is never logged.

Blank values count as "not set". `--token ""` does not override a token in
`SUVARI_MCP_TOKEN`; to run without authentication, unset the variable as well.

**Loopback without a token still works.** A loopback bind (`127.0.0.1`,
`localhost`, `::1`) needs no token, which is the default for local development.

**A non-loopback bind is refused without a token.** The server exits at startup
with:

```text
error: Refusing to bind 10.1.2.3 without authentication: set a bearer token with --token or SUVARI_MCP_TOKEN, or bind a loopback address.
```

### Network access (discouraged)

> **Warning:** authentication is **required** for non-loopback binds. It does
> not make network access safe: anyone who holds the token and can reach the
> port can run every tool on this machine, which is remote code execution by
> design. The token also travels in clear text over plain HTTP. Keep the default
> loopback bind unless the network is fully trusted.

Binding to anything other than loopback must be requested explicitly, and the
server logs a warning at startup:

```bash
# Discouraged: reachable from the network, token required
export SUVARI_MCP_TOKEN="$(openssl rand -hex 32)"
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
export SUVARI_MCP_TOKEN="$(openssl rand -hex 32)"
python suvari_mcp.py
ngrok http 8000 --host-header=localhost:8000
```

**Always set a token before starting a tunnel.** The server only sees a loopback
bind, so it cannot refuse to start without one, and the tunnel would publish an
unauthenticated server to the internet. The warning above applies in full.

## Transport Formats

| Transport | Endpoint | Clients |
|-----------|----------|---------|
| streamable-http (default) | `POST /mcp` | Claude Desktop, Cursor, Copilot |
| SSE | `GET /sse` + `POST /messages` | Claude Desktop (older), custom |
| JSON-RPC over HTTP | `POST /mcp` | Any HTTP client (curl, Python) |

## Connection Examples

### Python (requests)
```python
import os
import requests
s = requests.Session()
url = "http://localhost:8000/mcp"
token = os.environ["SUVARI_MCP_TOKEN"]
s.headers.update({"Authorization": f"Bearer {token}",
                  "Accept": "application/json, text/event-stream"})

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

Setting the headers on the session sends them with every request. For a single
call, pass `headers={"Authorization": f"Bearer {token}"}` to `requests.post`.

### curl
```bash
# Initialize
curl -s -X POST http://localhost:8000/mcp \
  -H "Authorization: Bearer $SUVARI_MCP_TOKEN" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl","version":"1"}},"id":1}'

# Tools list (with session ID from initialize response)
curl -s -X POST http://localhost:8000/mcp \
  -H "Authorization: Bearer $SUVARI_MCP_TOKEN" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <session_id>" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":2}'

# Run nmap
curl -s -X POST http://localhost:8000/mcp \
  -H "Authorization: Bearer $SUVARI_MCP_TOKEN" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <session_id>" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"nmap","arguments":{"target":"scanme.nmap.org","args":"-F"}},"id":3}'
```

## Available Tools

All installed Kali tools are available automatically:
`nmap`, `nuclei`, `gobuster`, `ffuf`, `sqlmap`, `hydra`, `whatweb`, `nikto`, `wpscan`, `masscan`, `curl`, `dig`, `dnsenum`, `dnsrecon`, `enum4linux`, `smbmap`, etc.

Run `python -c "from suvari.mcp_server import _get_runner; r=_get_runner(); print('\n'.join(sorted(r.available_tools())))"` for full list.

## Config for AI Clients

The snippets below send the token as a static header; replace `<token>` with its
value and leave `headers` out if the server runs on loopback without a token.
Clients without header support cannot authenticate, so they must stay on a
loopback server with no token. `suvari_mcp.py` only serves streamable HTTP; it
has no stdio transport.

### LM Studio
```json
{
  "mcpServers": {
    "suvari": {
      "url": "http://localhost:8000/mcp",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

### Cursor
```json
{
  "mcpServers": {
    "suvari": {
      "url": "http://localhost:8000/mcp",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

### VS Code Copilot
```json
{
  "servers": {
    "suvari": {
      "type": "http",
      "url": "http://localhost:8000/mcp",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

### Claude Code
```bash
claude mcp add --transport http suvari http://localhost:8000/mcp \
  --header "Authorization: Bearer $SUVARI_MCP_TOKEN"
```

### Claude Desktop
Its `mcpServers` config only starts stdio servers, so it cannot use
`suvari_mcp.py` directly and has no way to send a static header.
