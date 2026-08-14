"""
Suvari CLI — Typer-based command line interface.
"""

import typer
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from .orchestrator import SuvariOrchestrator
from .workspace import Workspace
from .config import configure_interactive, load_config
from .mode import ScanMode

console = Console()
app = typer.Typer(
    name="suvari",
    help="[SUVARI] Suvari — AI-Powered Black-Box Web Pentester",
    no_args_is_help=True,
)


def banner():
    console.print(Panel.fit(
        "[bold yellow][SUVARI][/bold yellow] — AI Cavalry\n"
        "[dim]Black-Box Web Pentester | Give the URL, Suvari handles the rest[/dim]",
        border_style="yellow"
    ))


def _resolve_provider(provider: str, model: Optional[str]) -> tuple:
    """Resolve provider/model: CLI arg > config > default."""
    cfg = load_config()
    if provider == "openai" and not model:
        cfg_provider = cfg.get("provider")
        cfg_model = cfg.get("model")
        if cfg_provider:
            provider = cfg_provider
        if cfg_model and not model:
            model = cfg_model
    return provider, model


@app.command()
def configure():
    """Interactive setup — provider, model, API key"""
    banner()
    configure_interactive()


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL (e.g. https://example.com)"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Scan name (optional)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory"),
    provider: str = typer.Option("openai", "--provider", "-p", help="LLM provider (openai/anthropic/deepseek/gemini/openrouter/ollama)"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name"),
    recon_only: bool = typer.Option(False, "--recon-only", help="Run recon only"),
    fast: bool = typer.Option(False, "--fast", "-f", help="Fast mode (fewer tests)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    mode: str = typer.Option("guided", "--mode", "-M", help="Scan mode: auto / guided / interactive"),
    parallel: int = typer.Option(3, "--parallel", "-P", help="Parallel tool count"),
    login: Optional[str] = typer.Option(None, "--login", "-l", help="Login credentials: username:password"),
    browser: str = typer.Option("auto", "--browser", "-b", help="Browser engine: auto / chromium / firefox / webkit"),
    server: bool = typer.Option(False, "--server", "-s", help="Full server scan (SSH, FTP, SMB, DB, all ports)"),
    source: Optional[Path] = typer.Option(None, "--source", "-r", help="Source code directory (white-box mode)"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080 for Burp/ZAP)"),
    headers: Optional[str] = typer.Option(None, "--headers", "-H", help="Custom headers (JSON format or 'Key: Value' pairs)"),
    cookies: Optional[str] = typer.Option(None, "--cookies", "-c", help="Custom cookies (JSON format or 'name=value' pairs)"),
    rate_limit: Optional[int] = typer.Option(None, "--rate-limit", help="Max requests per second (stealth mode)"),
    timeout: int = typer.Option(300, "--timeout", "-t", help="Tool timeout in seconds (default: 300)"),
    report_format: str = typer.Option("markdown", "--format", help="Report format: markdown / json / html / xml"),
    scope: Optional[str] = typer.Option(None, "--scope", help="Scope file (out-of-scope domains/paths to exclude)"),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", "-u", help="Custom User-Agent string"),
):
    """Scan target URL — recon → vulnerability scan → analysis → exploit → report
    
    Examples:
      suvari scan https://example.com
      suvari scan https://target.com --proxy http://127.0.0.1:8080
      suvari scan https://app.com -H '{"Authorization": "Bearer token"}' -c '{"session": "abc123"}'
      suvari scan https://site.com --rate-limit 5 --user-agent "Mozilla/5.0"
      suvari scan https://target.com --format json --scope scope.txt
    """
    banner()
    provider, model = _resolve_provider(provider, model)
    scan_mode = ScanMode.from_str(mode)
    ws = Workspace(name or url, output)
    console.print(f"[bold][TGT] Target:[/bold] {url}")
    console.print(f"[bold][AI] Model:[/bold] {provider}/{model or 'default'}")
    console.print(f"[bold][MODE]  Mode:[/bold] {scan_mode}")
    if source:
        console.print(f"[bold][DIR] Source:[/bold] {source} (white-box mode)")
    if server:
        console.print(f"[bold][SRV]  Mode:[/bold] Server scan (all ports + services)")
    if proxy:
        console.print(f"[bold][PROXY] Proxy:[/bold] {proxy}")
    if headers:
        console.print(f"[bold][HDR] Headers:[/bold] Custom headers enabled")
    if cookies:
        console.print(f"[bold][CKI] Cookies:[/bold] Custom cookies enabled")
    if rate_limit:
        console.print(f"[bold][RATE] Rate Limit:[/bold] {rate_limit} req/s")
    if user_agent:
        console.print(f"[bold][UA] User-Agent:[/bold] Custom UA set")
    if scope:
        console.print(f"[bold][SCP] Scope:[/bold] {scope}")
    console.print(f"[bold][DIR] Output:[/bold] {ws.path}")
    console.print(f"[bold][FMT] Format:[/bold] {report_format}\n")
    
    # Parse headers and cookies
    custom_headers = _parse_headers(headers)
    custom_cookies = _parse_cookies(cookies)
    
    orchestrator = SuvariOrchestrator(
        target_url=url,
        workspace=ws,
        provider=provider,
        model=model,
        recon_only=recon_only,
        fast=fast,
        verbose=verbose,
        scan_mode=scan_mode,
        parallel=parallel,
        chain_mode=True,
        login_creds=login,
        browser_type=browser,
        source_dir=source,
        server_scan=server,
        proxy_url=proxy,
        custom_headers=custom_headers,
        custom_cookies=custom_cookies,
        rate_limit=rate_limit,
        timeout=timeout,
        scope_file=scope,
        user_agent=user_agent,
        report_format=report_format,
    )
    orchestrator.run()
    # Save pointer to last scan
    try:
        (Path("output") / ".last").write_text(str(ws.path))
    except Exception:
        pass


def _parse_headers(headers_str: Optional[str]) -> dict:
    """Parse headers from JSON string or 'Key: Value' format."""
    if not headers_str:
        return {}
    
    import json
    try:
        # Try JSON format first
        return json.loads(headers_str)
    except json.JSONDecodeError:
        pass
    
    # Try 'Key: Value' format (one per line or comma-separated)
    headers = {}
    lines = headers_str.replace('\\n', '\n').split('\n')
    for line in lines:
        line = line.strip()
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
        elif ',' in line:
            # Handle comma-separated on single line
            for pair in line.split(','):
                if ':' in pair:
                    k, v = pair.split(':', 1)
                    headers[k.strip()] = v.strip()
    
    return headers


def _parse_cookies(cookies_str: Optional[str]) -> dict:
    """Parse cookies from JSON string or 'name=value' format."""
    if not cookies_str:
        return {}
    
    import json
    try:
        # Try JSON format first
        return json.loads(cookies_str)
    except json.JSONDecodeError:
        pass
    
    # Try 'name=value' format
    cookies = {}
    pairs = cookies_str.replace(';', ' ').split()
    for pair in pairs:
        if '=' in pair:
            key, value = pair.split('=', 1)
            cookies[key.strip()] = value.strip()
    
    return cookies


@app.command()
def recon(
    url: str = typer.Argument(..., help="Target URL"),
    provider: str = typer.Option("openai", "--provider", "-p"),
    model: Optional[str] = typer.Option(None, "--model", "-m"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Reconnaissance only (quick)"""
    banner()
    provider, model = _resolve_provider(provider, model)
    ws = Workspace(f"recon-{url}", output)
    console.print(f"[bold][TGT] Target:[/bold] {url}")
    orchestrator = SuvariOrchestrator(
        target_url=url,
        workspace=ws,
        provider=provider,
        model=model,
        recon_only=True,
        verbose=verbose,
    )
    orchestrator.run()


@app.command()
def report(
    path: Path = typer.Argument(..., help="Scan output directory"),
):
    """Show report from a previous scan"""
    banner()
    report_path = path / "report.md"
    if not report_path.exists():
        console.print("[red][ERR] report.md not found in that directory[/red]")
        raise typer.Exit(1)
    console.print(f"[bold][DOC] Report:[/bold] {report_path}")
    console.print(report_path.read_text())


@app.command()
def list():
    """List previous scans"""
    banner()
    output_dir = Path("output")
    if not output_dir.exists():
        console.print("[yellow]No scans found yet.[/yellow]")
        return
    for d in sorted(output_dir.iterdir()):
        if d.is_dir():
            report_file = d / "report.md"
            status = "[OK]" if report_file.exists() else "[RESUME]"
            console.print(f"  {status} {d.name}")


@app.command()
def chat():
    """Interactive pentesting chat — talk to Suvari naturally"""
    banner()
    from .chat import start
    start()


@app.command()
def bb(
    url: str = typer.Argument(..., help="Target URL (e.g. https://example.com)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory"),
):
    """Bug bounty recon — subdomains, URLs, params, tech"""
    banner()
    console.print(f"[bold][TGT] Target:[/bold] {url}")
    from .agents.bugbounty import BugBountyAgent
    from .llm import LLMClient
    from .workspace import Workspace
    from .tools.runner import ToolRunner
    cfg = load_config()
    llm = LLMClient(provider=cfg.get("provider", "deepseek"), model=cfg.get("model"))
    ws = Workspace(f"bb-{url.strip('/').split('/')[-1]}", output)
    tr = ToolRunner()
    agent = BugBountyAgent("bugbounty", llm, ws, tr)
    results = agent.run({"target_url": url})
    console.print(f"\n[green]Done![/green]")
    console.print(f"  Subdomains: {len(results.get('subdomains', []))}")
    console.print(f"  URLs: {len(results.get('urls', []))}")
    console.print(f"  Params: {len(results.get('params', []))}")
    console.print(f"  Tech: {len(results.get('technology', []))}")
    console.print(f"[dim]Output: {ws.path}[/dim]")


@app.command()
def attack(
    scan_dir: Optional[Path] = typer.Argument(None, help="Scan output directory (from previous scan)"),
    last: bool = typer.Option(False, "--last", "-l", help="Use most recent scan"),
    provider: str = typer.Option("openai", "--provider", "-p", help="LLM provider"),
    model: Optional[str] = None,
):
    """Targeted exploitation based on previous scan findings"""
    banner()
    from .agents.exploiter import ExploiterAgent
    from .llm import LLMClient
    from .workspace import Workspace
    from .tools.runner import ToolRunner
    from .report import ReportGenerator

    # Resolve scan directory
    if last or not scan_dir:
        last_file = Path("output") / ".last"
        if last_file.exists():
            scan_dir = Path(last_file.read_text().strip())
        elif not scan_dir:
            console.print("[red]Specify a scan directory or use --last[/red]")
            raise typer.Exit(1)

    # Read findings from scan output
    findings_file = scan_dir / "analysis" / "findings.json"
    if not findings_file.exists():
        # Try report.md
        report_file = scan_dir / "report.md"
        if report_file.exists():
            console.print(f"[yellow]No findings.json found, using report: {report_file}[/yellow]")
            report_text = report_file.read_text()
            findings = {"vulnerabilities": [], "summary": {"total": 0}}
        else:
            console.print("[red]No scan output found in that directory[/red]")
            raise typer.Exit(1)
    else:
        import json
        findings = json.loads(findings_file.read_text())

    import json
    vulns = findings.get("vulnerabilities", [])
    if not vulns:
        console.print("[yellow]No vulnerabilities found in scan results. Nothing to attack.[/yellow]")
        return

    console.print(f"[bold]Targeted attack on {len(vulns)} findings...[/bold]")
    for v in vulns:
        console.print(f"  [{v.get('severity','?')}] {v.get('type','?')} — {v.get('location','')}")

    # Run P-E-R exploitation loop (10 rounds max)
    cfg = load_config()
    prov, mod = _resolve_provider(provider, model)
    llm = LLMClient(provider=prov, model=mod)
    ws = Workspace(f"attack-{scan_dir.name}")
    tr = ToolRunner()
    avail = ", ".join(sorted(tr.available_tools().keys()))

    target = vulns[0].get("location", "").split("/")[0] if vulns else "https://example.com"
    tool_guide = """Web: nuclei, nikto, wpscan, httpx | Dir: gobuster, ffuf, feroxbuster, dirb
Net: nmap, masscan, netexec, responder | DNS: dnsenum, dnsrecon, fierce
Auth: hydra, sqlmap | SMB: enum4linux, smbmap, rpcclient
Info: whatweb, wafw00f, curl | Crack: john, hashcat | OSINT: amass, theharvester"""
    history = [{"role": "user", "content": f"Existing findings: {json.dumps(findings, indent=2)[:2000]}\n\nExploit each finding. Available tools:\n{tool_guide}\n\nUse the RIGHT tool. Don't just use curl. Use ```tool blocks."}]

    from rich.progress import Progress, SpinnerColumn, TextColumn
    console.print()

    for turn in range(10):
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task(f"Planning round {turn+1}...", total=None)
            response = llm.chat(messages=[{"role": "system", "content": f"You are an exploitation specialist. Verify findings by running actual security tools. Available: {avail}. Use ```tool blocks for commands. Be thorough."}] + history[-8:],
                              temperature=0.3, max_tokens=1024, stream=False)
            progress.update(task, description=f"Exploiting round {turn+1}...")

        # Extract and run commands
        cmds = []
        for m in __import__('re').finditer(r'```tool\n(.+?)\n```', response, __import__('re').DOTALL):
            c = m.group(1).strip()
            if c:
                cmds.append(c)
        if not cmds:
            console.print(response)
            history.append({"role": "assistant", "content": response})
            break

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            for cmd in cmds:
                task = progress.add_task(f"  Running: {cmd[:60]}...", total=None)
                try:
                    if "|" in cmd:
                        import subprocess as sp
                        r = sp.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
                        output = r.stdout[:1500] + r.stderr[:500]
                    else:
                        import shlex
                        output = tr.run(shlex.split(cmd), timeout=120)[:2000]
                except Exception as e:
                    output = f"(error: {e})"
                console.print(f"  $ {cmd}")
                progress.update(task, description="[green]Done[/green]")
                preview = output[:400].replace("\n", "\n  ")
                if preview:
                    console.print(f"  {preview}")

        history.append({"role": "assistant", "content": response})
        history.append({"role": "user", "content": f"Results:\n{output[:2000] if 'output' in dir() else 'done'}\n\nContinue exploitation or give final summary."})

    console.print(f"\n[green]Attack complete.[/green] [dim]{ws.path}[/dim]")


@app.command(name="pilot")
def pilot_cmd(target: str = typer.Argument(..., help="Target URL (e.g. https://example.com)"), model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name")):
    """Human-in-the-Loop interactive cockpit. AI suggests commands, you approve/edit/run.
    
    Unlike 'chat', Pilot gives you full control with AI assistance for each step.
    Perfect for manual pentesting with AI guidance.
    
    Example:
      suvari pilot https://target.com
      suvari pilot https://app.com -m claude-sonnet-4-5
    """
    banner()
    provider, model = _resolve_provider("openai", model)
    console.print(f"[bold][TGT] Target:[/bold] {target}")
    console.print(f"[bold][AI] Model:[/bold] {provider}/{model or 'default'}")
    console.print("[bold cyan]🚀 Starting Pilot Mode...[/bold cyan]\n")
    
    from .commands.pilot import PilotSession
    config = {"provider": provider, "model": model} if model else {"provider": provider}
    session = PilotSession(target, config)
    try:
        session.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Pilot session interrupted by user.[/yellow]")

@app.command()
def agent(target: str = typer.Argument(..., help="Target URL (e.g. https://example.com)"), 
          model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name")):
    """Human-directed AI Agent — Give orders, AI executes tools autonomously
    
    Unlike 'chat' (passive advice) or 'scan' (fully automated), 'agent' mode
    lets you give high-level orders which the AI executes using security tools.
    
    Examples:
      suvari agent https://target.com
      suvari agent https://app.com -m claude-sonnet-4
    
    Usage flow:
      Commander: "Scan the target for open ports"
      → AI plans and runs: nmap -sV -sC https://target.com
      → AI analyzes output and reports findings
      Commander: "Check for SQL injection on login form"
      → AI runs sqlmap with appropriate parameters
    """
    from .commands.agent import run_agent_command
    banner()
    try:
        run_agent_command(target, model=model)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Agent session interrupted by user.[/yellow]")

@app.command()
def last():
    """Show last scan report summary"""
    last_file = Path("output") / ".last"
    if not last_file.exists():
        console.print("[yellow]No scan has been run yet[/yellow]")
        return
    scan_dir = Path(last_file.read_text().strip())
    report_file = scan_dir / "report.md"
    if report_file.exists():
        console.print(f"[bold]Last scan:[/bold] {scan_dir.name}")
        console.print(report_file.read_text()[:2000])
    else:
        console.print(f"[yellow]No report found in {scan_dir}[/yellow]")

@app.command()
def help():
    """Show available commands and usage"""
    from rich.table import Table
    t = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 2))
    t.add_column("Command", style="cyan", no_wrap=True)
    t.add_column("Description", style="white")

    t.add_section()
    t.add_row("[bold]SETUP[/bold]", "")
    t.add_row("configure", "Provider, model, API key")

    t.add_section()
    t.add_row("[bold]SCAN[/bold]", "")
    t.add_row("scan <url>", "Full pipeline: recon -> scan -> analyze -> exploit -> report")
    t.add_row("  -f, --fast", "Quick scan (fewer tests)")
    t.add_row("  -s, --server", "All ports + SSH/FTP/SMB/DB")
    t.add_row("  -l, --login user:pass", "Authenticated scan")
    t.add_row("  -r, --source <dir>", "White-box with source code")
    t.add_row("  -b, --browser", "Browser engine: auto / chromium / firefox / webkit")
    t.add_row("  -P, --parallel <n>", "Parallel tools (default: 3)")
    t.add_row("  -M, --mode", "auto | guided | interactive")
    t.add_row("recon <url>", "Reconnaissance only (quick)")

    t.add_section()
    t.add_row("[bold]EXPLOIT[/bold]", "")
    t.add_row("attack <dir>", "Exploit previous scan findings")
    t.add_row("bb <url>", "Bug bounty: subdomains, URLs, params")

    t.add_section()
    t.add_row("[bold]OTHER[/bold]", "")
    t.add_row("chat", "Interactive chat + CTF")
    t.add_row("agent <url>", "Human-directed AI Agent — give orders, AI executes tools")
    t.add_row("pilot <url>", "Interactive cockpit — AI suggests, you approve/edit commands")
    t.add_row("report <dir>", "Show scan report")
    t.add_row("list", "List previous scans")
    t.add_row("help", "Show this message")

    t.add_section()
    t.add_row("[bold]MCP[/bold]", "python suvari_mcp.py")
    t.add_row("", "Tools: scan_target, recon_target, run_tool")
    t.add_row("", "list_available_tools, get_scan_report, analyze_ctf")

    console.print(t)
    console.print("\n[dim]Examples:[/dim]")
    console.print("  python suvari.py scan https://example.com")
    console.print("  python suvari.py scan https://server.com -s -P 5")
    console.print("  python suvari.py scan https://app.com -r ./src")
    console.print("  python suvari.py chat")
    console.print("  python suvari.py attack output/20260101_*/")
