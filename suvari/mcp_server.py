"""Suvari MCP Server — individual Kali tools as MCP tools.
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

# Bind to 0.0.0.0 for external access
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
    """
    Run any Kali Linux security tool against a target.
    Use this when there's no dedicated tool or you need custom parameters.

    Args:
        tool: Tool name (e.g. nmap, nuclei, gobuster, whatweb, nikto, curl, sqlmap)
        target: Target URL or host
        args: Additional tool arguments (e.g. "-T4 -F" for nmap, "dir" for gobuster subcommand)
        timeout: Max execution time in seconds (default 120)

    Returns:
        Tool output.
    """
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
        output = runner.run(cmd, timeout=timeout, max_output_len=100_000)
        return f"[{tool}] {target}\n\n{output[:8000]}"
    except Exception as e:
        return f"[{tool}] error: {e}"


@mcp.tool()
def list_available_tools() -> str:
    """
    List all Kali Linux security tools available on this system.
    """
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
    """
    Read a previous scan report or list recent scans.
    
    Args:
        scan_dir: Scan directory name. Leave empty to list recent scans.
    """
    output_dir = Path("output")
    if not scan_dir:
        if not output_dir.exists():
            return "No scans yet. Run a scan tool first."
        dirs = sorted(output_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
        if not dirs:
            return "No scans found."
        result = f"Recent scans ({len(dirs)} total):\n\n"
        for d in dirs[:10]:
            report = d / "report.md"
            status = "✓" if report.exists() else "⋯"
            result += f"  {status} {d.name}\n"
        return result

    report_path = Path(scan_dir)
    if not report_path.is_absolute():
        report_path = output_dir / scan_dir
    report_file = report_path / "report.md"
    if not report_file.exists():
        return f"Report not found."
    return report_file.read_text()[:8000]


# ── Known tool argument templates ──────────────────────────────────────────
# Tools listed here get smart argument handling. All other tools use generic
# fallback (tool + args + target).

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
    "subfinder":  (["-d", "{host}", "-silent"]),
    "amass":      (["enum", "-d", "{host}"]),
    "gau":        (["--domain", "{host}"]),
    "waybackurls":(["{host}"]),
    "arjun":      (["-u", "{target}"]),
    "paramspider":(["-d", "{host}"]),
    "katana":     (["-u", "{target}", "-silent"]),
    "hakrawler":  (["-u", "{target}", "-plain"]),
    "sslscan":    (["{host}"]),
    "sslyze":     (["{host}"]),
    "theharvester":(["-d", "{host}", "-b", "all"]),
    "enum4linux": (["{host}"]),
    "smbmap":     (["-H", "{host}"]),
}


def _make_tool_fn(tool_name: str):
    """Create an MCP tool function for ANY Kali tool."""
    def fn(target: str = "", args: str = "", timeout: int = 120) -> str:
        """Run {tool} against a target."""
        import logging
        log = logging.getLogger("suvari.mcp")
        log.info(f"Tool called: {tool_name} target={target} args={args!r} timeout={timeout}")
        runner = _get_runner()
        avail = runner.available_tools()
        if tool_name not in avail:
            return f"Tool '{tool_name}' not available on this system."
        
        host = target.split("://")[-1].split("/")[0]
        arg_list = args.split() if args else []

        # Build command: known template or generic fallback
        if tool_name in _KNOWN_CONFIGS:
            # Replace {target} and {host} placeholders
            template = _KNOWN_CONFIGS[tool_name]
            cmd = [tool_name]
            if not arg_list and not args:
                # No custom args: use full template
                for part in template:
                    cmd.append(part.replace("{target}", target).replace("{host}", host))
            else:
                # Custom args given: use template's initial flags + custom args + target
                static = [p for p in template if not p.startswith("{")]
                cmd = [tool_name] + arg_list + static
                if "{target}" in template:
                    cmd.append(target)
                elif "{host}" in template:
                    cmd.append(host)
        else:
            # Generic fallback: tool + args + target
            cmd = [tool_name] + arg_list + ([target] if target else [])

        try:
            output = runner.run(cmd, timeout=timeout, max_output_len=100_000)
            
            # Smart timeout handling: retry once with longer timeout
            if output.startswith("(TIMEOUT") and timeout < 300:
                retry_timeout = min(timeout * 2, 300)
                log.info(f"  {tool_name} timeout at {timeout}s, retrying with {retry_timeout}s")
                # For directory busters: reduce thread count on retry
                if tool_name in ("gobuster", "dirb", "ffuf"):
                    retry_cmd = cmd + ["-t", "10"] if tool_name == "gobuster" else cmd
                else:
                    retry_cmd = cmd
                output = runner.run(retry_cmd, timeout=retry_timeout, max_output_len=100_000)
                if output.startswith("(TIMEOUT"):
                    return f"[{tool_name}] {target} — site yanıt vermiyor veya engelliyor (timeout {retry_timeout}s)"
            
            return f"[{tool_name}] {target}\n\n{output[:8000]}"
        except Exception as e:
            return f"[{tool_name}] error: {e}"

    fn.__name__ = tool_name
    fn.__doc__ = f"""Run {tool_name} against a target.
    
    Args:
        target: Target URL or host
        args: Additional tool arguments
        timeout: Max execution time in seconds (default 120)

    Returns:
        Tool output.
    """
    return fn


# ── Register ALL available tools dynamically ───────────────────────────────

runner_check = _get_runner()
all_tools = runner_check.available_tools()
for tool_name in sorted(all_tools.keys()):
    fn = _make_tool_fn(tool_name)
    mcp.add_tool(fn, name=tool_name)

logger = logging.getLogger("suvari.mcp")
logger.info(f"MCP ready: {len(all_tools)} tools registered (all available Kali tools)")


# ── Entry point ────────────────────────────────────────────────────────────

def run_mcp(transport: Literal["stdio", "sse", "streamable-http"] = "streamable-http"):
    """Start the MCP server.
    
    Args:
        transport: 'streamable-http' (default, POST /mcp),
                   'stdio' (for Claude Desktop),
                   or 'sse' (SSE event stream)
    """
    if transport == "streamable-http":
        print(f"\n  ╔═══════════════════════════════════════════════╗", flush=True)
        print(f"  ║        🐴  SUVARI — AI KALVALRY           ║", flush=True)
        print(f"  ║     {len(_get_runner().available_tools())} Kali tools ready for battle    ║", flush=True)
        print(f"  ╚═══════════════════════════════════════════════╝", flush=True)
        print(f"  🎯  Endpoint: POST /mcp", flush=True)
        print(f"  🌐  http://localhost:8000/mcp", flush=True)
        print(f"  📋  Headers: Content-Type: application/json", flush=True)
        print(f"  🔌  Accept: application/json, text/event-stream", flush=True)
        print(flush=True)
    mcp.run(transport=transport)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Suvari MCP — Kali tools for AI agents")
    parser.add_argument("--sse", action="store_true", help="SSE transport instead of streamable-http")
    parser.add_argument("--list-tools", action="store_true", help="List all tools and exit")
    args = parser.parse_args()

    if args.list_tools:
        runner_check = _get_runner()
        actual_tools = runner_check.available_tools()
        print(f"Suvari MCP — {len(actual_tools)} Kali tools available:\n")
        for name, desc in sorted(actual_tools.items()):
            print(f"    {name}: {desc}")
        sys.exit(0)

    transport = "sse" if args.sse else "streamable-http"
    run_mcp(transport)
