"""
Suvari MCP Server — individual Kali tools as MCP tools.
Each available Kali tool is its own MCP tool for AI agents.
"""

import sys
import logging
from typing import Literal
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pathlib import Path
from .tools.runner import ToolRunner

# Suppress MCP internal noise
logging.getLogger("mcp").setLevel(logging.WARNING)

mcp = FastMCP("Suvari — AI Pentester",
    instructions="80+ Kali Linux security tools as individual MCP tools. Use run_tool for any tool, or call the specific tool directly.",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    debug=True,
)

import os
_MCP_HOST = os.environ.get("MCP_HOST", "0.0.0.0")
_MCP_PORT = int(os.environ.get("MCP_PORT", "8000"))

_runner = None
def _get_runner():
    global _runner
    if _runner is None:
        _runner = ToolRunner()
    return _runner


# ── Generic tool runner (catch-all) ────────────────────────────────────────

@mcp.tool()
def run_tool(
    tool: str,
    target: str = "",
    args: str = "",
    timeout: int = 120,
) -> str:
    """Run any Kali Linux security tool."""
    runner = _get_runner()
    avail = runner.available_tools()
    if tool not in avail:
        return f"Tool '{tool}' not available on this system."
    host = target.split("://")[-1].split("/")[0]
    arg_list = args.split() if args else []
    tool_configs = {
        "nuclei":    ["nuclei"] + arg_list + ["-u", target],
        "nikto":     ["nikto", "-h", target] + arg_list + ["-nointeractive"],
        "gobuster":  ["gobuster"] + (arg_list or ["dir"]) + ["-u", target, "-w", "/usr/share/wordlists/dirb/common.txt", "-q"],
        "ffuf":      ["ffuf"] + arg_list + ["-u", f"{target}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-s"],
        "dirb":      ["dirb", target] + arg_list,
        "whatweb":   ["whatweb", target] + arg_list,
        "wpscan":    ["wpscan", "--url", target] + arg_list + ["--no-update"],
        "nmap":      ["nmap"] + arg_list + [host],
        "masscan":   ["masscan"] + arg_list + [host],
        "curl":      ["curl", "-sL", target] + arg_list,
        "sqlmap":    ["sqlmap", "-u", target, "--batch"] + arg_list,
        "hydra":     ["hydra"] + arg_list + [host],
        "wafw00f":   ["wafw00f", target] + arg_list,
        "dalfox":    ["dalfox", "url", target] + arg_list + ["--silence"],
        "httpx":     ["httpx", "-u", target] + arg_list,
        "dnsrecon":  ["dnsrecon", "-d", host] + arg_list,
        "fierce":    ["fierce", "--domain", host] + arg_list,
        "dnsenum":   ["dnsenum", host] + arg_list,
    }
    try:
        cmd = tool_configs.get(tool, [tool] + arg_list + ([target] if target else []))
        output = runner.run(cmd, timeout=timeout)
        return f"[{tool}] {target}\n\n{output[:8000]}"
    except Exception as e:
        return f"[{tool}] error: {e}"


@mcp.tool()
def list_available_tools() -> str:
    """List all Kali tools available on this system."""
    runner = _get_runner()
    avail = runner.available_tools()
    if not avail:
        return "No security tools found on this system."
    result = f"Available tools ({len(avail)}):\n\n"
    for name, desc in sorted(avail.items()):
        result += f"  {name}: {desc}\n"
    return result


@mcp.tool()
def get_scan_report(scan_dir: str = "") -> str:
    """Read a previous scan report or list recent scans."""
    output_dir = Path("output")
    if not scan_dir:
        if not output_dir.exists():
            return "No scans yet."
        dirs = sorted(output_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
        result = f"Recent scans ({len(dirs)} total):\n\n"
        for d in dirs[:10]:
            report = d / "report.md"
            result += f"  {'✓' if report.exists() else '⋯'} {d.name}\n"
        return result
    report_path = Path(scan_dir)
    if not report_path.is_absolute():
        report_path = output_dir / scan_dir
    report_file = report_path / "report.md"
    if not report_file.exists():
        return f"Report not found."
    return report_file.read_text()[:8000]


# ── Dynamic tool registration ──────────────────────────────────────────────

_KNOWN_CONFIGS = {
    "nuclei":     (["-u", "{target}"]),
    "nikto":      (["-h", "{target}", "-nointeractive"]),
    "gobuster":   (["dir", "-u", "{target}", "-w", "/usr/share/wordlists/dirb/common.txt", "-q"]),
    "ffuf":       (["-u", "{target}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-s"]),
    "dirb":       (["{target}"]),
    "whatweb":    (["{target}"]),
    "wpscan":     (["--url", "{target}", "--no-update"]),
    "nmap":       (["{host}"]),
    "masscan":    (["{host}"]),
    "curl":       (["-sL", "{target}"]),
    "sqlmap":     (["-u", "{target}", "--batch"]),
    "hydra":      (["{host}"]),
    "wafw00f":    (["{target}"]),
    "dalfox":     (["url", "{target}", "--silence"]),
    "httpx":      (["-u", "{target}"]),
    "dnsrecon":   (["-d", "{host}"]),
    "fierce":     (["--domain", "{host}"]),
    "dnsenum":    (["{host}"]),
}

def _make_tool_fn(tool_name: str):
    def fn(target: str = "", args: str = "", timeout: int = 120) -> str:
        runner = _get_runner()
        avail = runner.available_tools()
        if tool_name not in avail:
            return f"Tool '{tool_name}' not available."
        host = target.split("://")[-1].split("/")[0]
        arg_list = args.split() if args else []
        if tool_name in _KNOWN_CONFIGS:
            template = _KNOWN_CONFIGS[tool_name]
            cmd = [tool_name]
            if not arg_list:
                for part in template:
                    cmd.append(part.replace("{target}", target).replace("{host}", host))
            else:
                static = [p for p in template if not p.startswith("{")]
                cmd = [tool_name] + arg_list + static
                if "{target}" in template:
                    cmd.append(target)
                elif "{host}" in template:
                    cmd.append(host)
        else:
            cmd = [tool_name] + arg_list + ([target] if target else [])
        try:
            output = runner.run(cmd, timeout=timeout)
            if output.startswith("(TIMEOUT") and timeout < 300:
                output = runner.run(cmd, timeout=min(timeout * 2, 300))
                if output.startswith("(TIMEOUT"):
                    return f"[{tool_name}] {target} — timeout"
            return f"[{tool_name}] {target}\n\n{output[:8000]}"
        except Exception as e:
            return f"[{tool_name}] error: {e}"
    fn.__name__ = tool_name
    fn.__doc__ = f"Run {tool_name} against a target."
    return fn

runner_check = _get_runner()
all_tools = runner_check.available_tools()
for tool_name in sorted(all_tools.keys()):
    fn = _make_tool_fn(tool_name)
    mcp.add_tool(fn, name=tool_name)

logger = logging.getLogger("suvari.mcp")
logger.info(f"MCP ready: {len(all_tools)} tools registered")


# ── Multi-transport server ────────────────────────────────────────────────

def run_server(host: str = "0.0.0.0", port: int = 8000):
    """Run MCP server supporting ALL transports simultaneously."""
    import uvicorn
    from starlette.applications import Starlette
    from starlette.routing import Mount, Route
    from starlette.middleware import Middleware
    from starlette.middleware.cors import CORSMiddleware
    from starlette.responses import JSONResponse

    # Build unified app
    sse_app = mcp.sse_app()
    streamable_app = mcp.streamable_http_app()
    from starlette.responses import JSONResponse
    from starlette.requests import Request

    async def health(request: Request):
        return JSONResponse({"status": "ok", "tools": len(all_tools)})

    async def mcp_get(request: Request):
        """GET /mcp returns 405 - use POST."""
        return JSONResponse({"error": "use POST with JSON-RPC body", "help": "POST {\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}"}, status_code=405)

    routes = [
        Route("/", endpoint=health),
        Route("/health", endpoint=health),
        Route("/mcp", endpoint=mcp_get, methods=["GET"]),
        Mount("/mcp", app=streamable_app),  # POST handled by streamable-http
        # SSE transport at /sse
        Mount("/", app=sse_app),
    ]

    app = Starlette(
        routes=routes,
        middleware=[
            Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]),
        ],
    )

    # Log POST /mcp requests and responses
    import logging
    import json as _json
    log = logging.getLogger("suvari.mcp")

    # ── Simple REST API (no MCP complexity) ──────────────────────────
    async def api_list_tools(request: Request):
        """GET /api/tools — list all available tools."""
        runner = _get_runner()
        tools = runner.available_tools()
        return JSONResponse({"tools": [{"name": n, "description": d} for n, d in sorted(tools.items())]})

    async def api_run_tool(request: Request):
        """POST /api/run — run a tool.
        Body: {"tool": "nmap", "target": "scanme.nmap.org", "args": "-F"}
        """
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)
        tool = data.get("tool", "")
        target = data.get("target", "")
        args = data.get("args", "")
        if not tool:
            return JSONResponse({"error": "tool required"}, status_code=400)
        # Run via existing MCP tool logic
        fn = _make_tool_fn(tool)
        result = fn(target=target, args=args)
        return JSONResponse({"tool": tool, "target": target, "output": result[:5000]})

    async def api_health(request: Request):
        return JSONResponse({"status": "ok", "tools": len(all_tools), "version": "1.0"})

    # Add routes
    routes += [
        Route("/api/tools", endpoint=api_list_tools, methods=["GET"]),
        Route("/api/run", endpoint=api_run_tool, methods=["POST"]),
        Route("/api/health", endpoint=api_health, methods=["GET"]),
    ]

    @app.middleware("http")
    async def log_mcp(request, call_next):
        if request.method == "POST" and request.url.path == "/mcp":
            body = await request.body()
            log.info(f"POST /mcp from {request.client.host}: {body[:500]}")
        response = await call_next(request)
        if request.method == "POST" and request.url.path == "/mcp":
            resp_body = b"".join([chunk async for chunk in response.body_iterator])
            log.info(f"Response ({response.status_code}): {resp_body[:500]}")
            from starlette.responses import Response
            return Response(content=resp_body, status_code=response.status_code, media_type="application/json", headers=dict(response.headers))
        return response

    print(f"Suvari MCP on {host}:{port}")
    print(f"  POST /mcp     — streamable-http (JSON-RPC)")
    print(f"  GET  /sse     — SSE transport")
    print(f"  GET  /health  — health check")
    print(f"  {len(all_tools)} tools available")

    uvicorn.run(app, host=host, port=port, log_level="info")


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Suvari MCP — Kali tools for AI agents")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=8000, help="Port")
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)
