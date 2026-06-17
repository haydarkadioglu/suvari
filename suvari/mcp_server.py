"""
Suvari MCP Server — exposes Suvari's capabilities as MCP tools.
Compatible with Claude Desktop, Cursor, VS Code Copilot, and any MCP client.
"""

from mcp.server.fastmcp import FastMCP
from pathlib import Path
from .orchestrator import SuvariOrchestrator
from .workspace import Workspace
from .config import load_config
from .tools.runner import ToolRunner
from .mode import ScanMode


mcp = FastMCP("Suvari — AI Pentester")

def _get_llm():
    from .llm import LLMClient
    cfg = load_config()
    return LLMClient(provider=cfg.get("provider", "deepseek"), model=cfg.get("model"))


@mcp.tool()
def scan_target(
    url: str,
    fast: bool = False,
    server: bool = False,
) -> str:
    """
    Run a full security scan on a target URL.
    Performs recon, vulnerability scanning, AI analysis, and generates a report.

    Args:
        url: Target URL (e.g. https://example.com)
        fast: Fast mode - fewer tests, quicker results
        server: Server mode - scan all ports and services (SSH, FTP, SMB, etc.)

    Returns:
        Scan results summary with findings and report path.
    """
    try:
        ws = Workspace(url)
        orchestrator = SuvariOrchestrator(
            target_url=url,
            workspace=ws,
            recon_only=False,
            fast=fast,
            verbose=False,
            scan_mode=ScanMode.AUTO,
            server_scan=server,
        )
        orchestrator.run()
        analysis = orchestrator.context.get("analysis", {})
        summary = analysis.get("summary", {})
        vulns = analysis.get("vulnerabilities", [])
        result = f"Scan complete for {url}\n"
        result += f"Findings: {summary.get('total', 0)} total "
        result += f"({summary.get('critical', 0)} critical, {summary.get('high', 0)} high, "
        result += f"{summary.get('medium', 0)} medium)\n\n"
        for v in vulns[:5]:
            result += f"- [{v.get('severity','?')}] {v.get('type','?')}: {v.get('location','')}\n"
        result += f"\nReport: {ws.path / 'report.md'}"
        return result
    except Exception as e:
        return f"Scan error: {e}"


@mcp.tool()
def recon_target(url: str) -> str:
    """
    Run reconnaissance only on a target URL.
    Quickly gathers technology info, open ports, and basic exposure.

    Args:
        url: Target URL

    Returns:
        Reconnaissance results: technology stack, open ports, exposed files.
    """
    try:
        from .agents.recon import ReconAgent
        llm = _get_llm()
        ws = Workspace(f"recon-{url.split('/')[-1]}")
        tr = ToolRunner()
        agent = ReconAgent("recon", llm, ws, tr)
        results = agent.run({"target_url": url, "fast": True})
        out = f"Recon complete for {url}\n\n"
        if results.get("whatweb"):
            out += f"Technology:\n{results['whatweb'][:400]}\n\n"
        if results.get("nmap"):
            out += f"Ports:\n{results['nmap'][:400]}\n\n"
        if results.get("common_paths"):
            out += f"Exposed paths:\n{results['common_paths'][:200]}\n"
        return out
    except Exception as e:
        return f"Recon error: {e}"


@mcp.tool()
def run_tool(
    tool: str,
    target: str,
    args: str = "",
) -> str:
    """
    Run a specific security tool against a target.

    Args:
        tool: Tool name (e.g. nmap, nuclei, gobuster, sqlmap, whatweb, nikto)
        target: Target URL or host
        args: Additional arguments as space-separated string (e.g. "-T4 -F")

    Returns:
        Tool output.
    """
    try:
        tr = ToolRunner()
        avail = tr.available_tools()
        if tool not in avail:
            return f"Tool '{tool}' not available. Available: {', '.join(avail.keys())}"

        arg_list = args.split() if args else []
        cmd = [tool] + arg_list

        if tool in ("nuclei", "gobuster", "ffuf", "sqlmap"):
            cmd += ["-u", target]
        elif tool in ("nikto",):
            cmd += [target]
        elif tool == "nmap":
            cmd += [target.split("://")[-1].split("/")[0]]
        elif tool == "whatweb":
            cmd += [target]
        elif tool == "httpx":
            cmd += ["-u", target]
        else:
            cmd += [target]

        output = tr.run(cmd, timeout=120)
        return f"[{tool}] {target}\n\n{output[:2000]}"
    except Exception as e:
        return f"Tool error: {e}"


@mcp.tool()
def list_available_tools() -> str:
    """
    List all security tools available on the system.

    Returns:
        Categorized list of available tools with descriptions.
    """
    tr = ToolRunner()
    avail = tr.available_tools()
    if not avail:
        return "No security tools found."
    result = f"Available tools ({len(avail)}):\n\n"
    for name, desc in sorted(avail.items()):
        result += f"  {name}: {desc}\n"
    return result


@mcp.tool()
def get_scan_report(scan_dir: str) -> str:
    """
    Get the report from a previous scan.

    Args:
        scan_dir: Path to the scan output directory (from a previous scan)

    Returns:
        Scan report content in Markdown.
    """
    try:
        report = Path(scan_dir) / "report.md"
        if not report.exists():
            dirs = list(Path("output").iterdir()) if Path("output").exists() else []
            return f"Report not found at {scan_dir}. Recent scans: {[d.name for d in sorted(dirs)[-5:]]}"
        return report.read_text()[:5000]
    except Exception as e:
        return f"Error reading report: {e}"


@mcp.tool()
def analyze_ctf(description: str) -> str:
    """
    Analyze a CTF challenge based on a description.
    Finds relevant files in the current directory and suggests tools/approaches.

    Args:
        description: Natural language description of the CTF challenge
                     (e.g. "pcap file with DNS exfiltration",
                      "binary with buffer overflow", "steganography in image")

    Returns:
        Analysis and suggested tools/commands for the challenge.
    """
    import subprocess
    from pathlib import Path

    cwd = Path.cwd()
    files = []
    for f in sorted(cwd.iterdir())[:20]:
        if f.is_file() and not f.name.startswith("."):
            try:
                kind = subprocess.run(["file", "-b", str(f)], capture_output=True, text=True, timeout=5).stdout.strip()[:60]
                files.append(f"  {f.name}: {kind} ({f.stat().st_size}b)")
            except Exception:
                files.append(f"  {f.name}: ({f.stat().st_size}b)")

    file_context = "\n".join(files) if files else "  No files found."

    llm = _get_llm()
    prompt = f"""CTF Challenge: {description}

Files in current directory:
{file_context}

Suggest specific tools and commands for this CTF challenge.
Be direct and actionable."""

    try:
        response = llm.chat(messages=[{"role": "user", "content": prompt}], temperature=0.5, max_tokens=1024)
        return response
    except Exception as e:
        return f"Error: {e}"
