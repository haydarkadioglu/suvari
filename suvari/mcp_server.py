"""
Suvari MCP Server — individual Kali tools as MCP tools.
Each available Kali tool is its own MCP tool for AI agents.
"""

import ipaddress
import json
import os
import secrets
import sys
import logging
from typing import Literal
import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pathlib import Path
from starlette.types import ASGIApp, Receive, Scope, Send
from .tools.runner import ToolRunner

# Suppress MCP internal noise
logging.getLogger("mcp").setLevel(logging.WARNING)


def configure_logging(level: int = logging.INFO) -> None:
    """Configure root logging so module log lines reach the console.

    Idempotent: ``logging.basicConfig`` is a no-op once the root logger has
    handlers, so calling this twice does not add duplicate handlers.
    """
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


_DEFAULT_HOST = "127.0.0.1"
_TOKEN_ENV = "SUVARI_MCP_TOKEN"
_LOOPBACK_ALLOWED_HOSTS: tuple[str, ...] = ("127.0.0.1:*", "localhost:*", "[::1]:*")
_LOOPBACK_ALLOWED_ORIGINS: tuple[str, ...] = (
    "http://127.0.0.1:*",
    "http://localhost:*",
    "http://[::1]:*",
)


def default_host() -> str:
    """Return the bind address used when --host is not given.

    An empty ``MCP_HOST`` falls back to loopback: passing "" to the server
    would bind every interface.
    """
    return os.environ.get("MCP_HOST") or _DEFAULT_HOST


def default_port() -> int:
    """Return the port used when --port is not given."""
    return int(os.environ.get("MCP_PORT", "8000"))


def is_wildcard_host(host: str) -> bool:
    """Return True if ``host`` means "every interface" rather than one address."""
    return host.strip("[]") in ("0.0.0.0", "::")


def is_loopback_host(host: str) -> bool:
    """Return True if ``host`` only accepts connections from this machine."""
    normalized = host.strip("[]").lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def build_transport_security(host: str) -> TransportSecuritySettings:
    """Build DNS-rebinding settings for a server bound to ``host``.

    Protection is always enabled. Loopback patterns are always allowed, and
    ``host`` itself is added so the server does not reject, on the Host header,
    connections it accepted on that address.
    """
    allowed_hosts = list(_LOOPBACK_ALLOWED_HOSTS)
    allowed_origins = list(_LOOPBACK_ALLOWED_ORIGINS)
    # IPv6 literals appear bracketed in Host and Origin headers
    url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if f"{url_host}:*" not in allowed_hosts:
        allowed_hosts.append(f"{url_host}:*")
        allowed_origins.append(f"http://{url_host}:*")
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )


def resolve_token(cli_token: str | None = None) -> str | None:
    """Return the bearer token to require, or None when authentication is disabled.

    Precedence: explicit argument, then SUVARI_MCP_TOKEN. Blank values are ignored,
    because an empty token would accept ``Authorization: Bearer `` and disable auth
    without the operator noticing.
    """
    for candidate in (cli_token, os.environ.get(_TOKEN_ENV)):
        if candidate and candidate.strip():
            return candidate.strip()
    return None


def validate_bind(host: str, token: str | None) -> None:
    """Refuse to expose an unauthenticated server on a non-loopback address."""
    if token is None and not is_loopback_host(host):
        raise ValueError(
            f"Refusing to bind {host} without authentication: set a bearer token with "
            f"--token or {_TOKEN_ENV}, or bind a loopback address."
        )


class BearerTokenMiddleware:
    """Pure ASGI middleware that requires ``Authorization: Bearer <token>``.

    Implemented as ASGI (not BaseHTTPMiddleware) so it also covers requests that
    never reach the routing layer and so streaming responses stay untouched.
    """

    def __init__(self, app: ASGIApp, token: str) -> None:
        if not token or not token.strip():
            raise ValueError("Bearer token must not be empty")
        self.app = app
        self._token = token.encode()

    def _is_authorized(self, scope: Scope) -> bool:
        for name, value in scope.get("headers", []):
            if name.lower() == b"authorization":
                parts = value.split(None, 1)
                return (
                    len(parts) == 2
                    and parts[0].lower() == b"bearer"
                    and secrets.compare_digest(parts[1].strip(), self._token)
                )
        return False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self._is_authorized(scope):
            await self.app(scope, receive, send)
            return
        logger.warning("Rejected unauthenticated MCP request from %s", scope.get("client"))
        body = json.dumps(
            {"error": "unauthorized", "detail": "missing or invalid bearer token"}
        ).encode()
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"www-authenticate", b'Bearer realm="suvari"'),
            ],
        })
        await send({"type": "http.response.body", "body": body})


mcp = FastMCP("Suvari — AI Pentester",
    instructions="80+ Kali Linux security tools as individual MCP tools. Use run_tool for any tool, or call the specific tool directly.",
    transport_security=build_transport_security(_DEFAULT_HOST),
    debug=True,
)

_MCP_HOST = default_host()
_MCP_PORT = default_port()

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
    "ftp":        (["{host}"]),
    "wget":       (["{target}"]),
    "nc":         (["{host}"]),
    "telnet":     (["{host}"]),
    "python3":    (["-c", "{target}"]),
    "python":     (["-c", "{target}"]),
    "perl":       (["-e", "{target}"]),
    "ruby":       (["-e", "{target}"]),
    "sh":         (["-c", "{target}"]),
    "bash":       (["-c", "{target}"]),
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

def run_server(host: str = "127.0.0.1", port: int = 8000, token: str | None = None) -> None:
    """Run MCP streamable-http server with request logging."""
    import logging
    token = resolve_token(token)
    validate_bind(host, token)
    logging.getLogger("mcp").setLevel(logging.INFO)

    # Print tool name when called
    mcp._orig_log = logging.getLogger("mcp.server.server").info
    def log_hook(msg, *args, **kwargs):
        # Catch CallToolRequest which contains the tool name
        if "CallTool" in str(msg) or "handle_" in str(msg):
            import re
            match = re.search(r"CallToolRequest\('([^']+)'", str(args))
            if match:
                print(f"  [MCP] tool: {match.group(1)}")
        mcp._orig_log(msg, *args, **kwargs)
    logging.getLogger("mcp.server.server").info = log_hook

    mcp.settings.host = host
    mcp.settings.port = port
    mcp.settings.transport_security = build_transport_security(host)
    if not is_loopback_host(host):
        logger.warning(
            "!!! Suvari MCP is bound to %s and is REACHABLE FROM THE NETWORK. "
            "Anyone who holds the bearer token and can reach port %s can run every "
            "tool on this machine. !!!",
            host,
            port,
        )
        logger.info("Bearer-token authentication is enabled")
        if is_wildcard_host(host):
            logger.warning(
                "Host header validation only accepts '%s', so clients connecting through a "
                "real address get '421 Invalid Host header'. Bind the specific interface "
                "address (for example --host 10.1.2.3) instead of a wildcard.",
                host,
            )
    auth_note = " (auth: bearer token)" if token is not None else ""
    print(f"Suvari MCP: streamable-http on {host}:{port}{auth_note}")
    print(f"  POST /mcp - JSON-RPC")
    # Built after transport_security is set: the session manager captures it on first call
    app = mcp.streamable_http_app()
    if token is not None:
        app = BearerTokenMiddleware(app, token)
    uvicorn.run(app, host=host, port=port, log_level="warning")


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Suvari MCP — Kali tools for AI agents")
    parser.add_argument("--host", default=default_host(), help="Bind address (default: loopback)")
    parser.add_argument("--port", type=int, default=default_port(), help="Port")
    parser.add_argument(
        "--token",
        default=resolve_token(),
        help="Bearer token required from clients (default: $SUVARI_MCP_TOKEN; empty disables auth)",
    )
    args = parser.parse_args()
    try:
        run_server(host=args.host, port=args.port, token=args.token)
    except ValueError as exc:
        # A refused bind must not look like a crash: print the reason and exit 1
        raise SystemExit(f"error: {exc}") from None
