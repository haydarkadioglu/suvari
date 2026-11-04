"""
Suvari CLI — Typer-based command line interface.
"""

import logging
import typer
from typing import List, Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from .orchestrator import SuvariOrchestrator
from .workspace import Workspace
from .config import configure_interactive, load_config
from .mode import ScanMode
from .logging_setup import LEVEL_NAMES, configure_logging, log_swallowed

log = logging.getLogger("suvari.cli")
console = Console()
app = typer.Typer(
    name="suvari",
    help="[SUVARI] Suvari — AI-Powered Black-Box Web Pentester",
    no_args_is_help=True,
)


@app.callback()
def _global_options(
    log_level: str = typer.Option(
        "warning", "--log-level",
        help=f"Log verbosity: {', '.join(LEVEL_NAMES)}",
    ),
    debug: bool = typer.Option(False, "--debug", help="Debug logging with tracebacks"),
) -> None:
    """[SUVARI] Suvari — AI-Powered Black-Box Web Pentester"""
    try:
        configure_logging(log_level, debug=debug)
    except ValueError as e:
        raise typer.BadParameter(str(e), param_hint="--log-level")


def _write_last_pointer(target: Path) -> bool:
    """Record ``target`` in ``output/.last``; returns False if that fails."""
    last_file = Path("output") / ".last"
    try:
        last_file.write_text(str(target))
    except Exception as e:
        log_swallowed(log, "could not write last-scan pointer %s", e, last_file)
        return False
    return True


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
):
    """Scan target URL — recon → vulnerability scan → analysis → report"""
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
    console.print(f"[bold][DIR] Output:[/bold] {ws.path}\n")
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
    )
    orchestrator.run()
    # Save pointer to last scan
    _write_last_pointer(ws.path)


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
                        output = tr.run_pipeline(cmd, timeout=120)[:2000]
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


RESUME_LATEST = "latest"


@app.command()
def auto(
    url: Optional[str] = typer.Argument(None, help="Target URL (single-target shorthand for --target)"),
    target: List[str] = typer.Option([], "--target", "-t", help="Target: URL, host:port, IP, CIDR or IP range (repeatable)"),
    targets_file: Optional[Path] = typer.Option(None, "--targets", help="File with one target per line"),
    scope_file: Optional[Path] = typer.Option(None, "--scope-file", help="Explicit scope allowlist file (default: the targets themselves)"),
    allow_large_scope: bool = typer.Option(False, "--allow-large-scope", help="Permit networks/ranges wider than a /24"),
    duration: Optional[str] = typer.Option(None, "--duration", help="Job time budget, e.g. 30m, 2h (default: --time-budget)"),
    max_requests: Optional[int] = typer.Option(None, "--max-requests", help="Total request budget for the job"),
    max_tokens: Optional[int] = typer.Option(None, "--max-tokens", help="Total LLM token budget for the job"),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", help="Targets scanned in parallel (default 1)"),
    resume: Optional[str] = typer.Option(None, "--resume", help="Resume a job by id (bare --resume: most recent unfinished job)"),
    jobs: bool = typer.Option(False, "--jobs", help="List jobs and exit"),
    jobs_dir: Path = typer.Option(Path("output") / "jobs", "--jobs-dir", help="Where jobs are stored"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Legacy single-target workspace directory"),
    provider: str = typer.Option("openai", "--provider", "-p", help="LLM provider"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name"),
    max_steps: int = typer.Option(20, "--max-steps", help="Maximum probe turns per target"),
    time_budget: float = typer.Option(300.0, "--time-budget", help="Wall-clock budget in seconds (used when --duration is not set)"),
    rate_per_min: Optional[int] = typer.Option(None, "--rate", help="Max requests per minute, global across targets (default 60)"),
    allow_host: List[str] = typer.Option([], "--allow-host", help="Extra in-scope host(s)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Deterministic engine, no LLM"),
):
    """Autonomous probability-driven scan — multi-target, resumable jobs"""
    from .auto.jobs import JobManager

    manager = JobManager(jobs_dir)
    if jobs:
        _print_jobs(manager)
        return

    banner()
    provider, model = _resolve_provider(provider, model)

    # Legacy single-workspace engine: kept verbatim for `--output` users.
    if output is not None:
        if not url:
            console.print("[red]--output needs a positional URL (legacy single-target mode).[/red]")
            raise typer.Exit(2)
        _auto_legacy(url, output, provider, model, max_steps, time_budget,
                     rate_per_min or 60, allow_host, resume is not None, dry_run,
                     max_tokens=max_tokens)
        return

    from .auto.jobs import parse_duration
    from .auto.scope import ScopeError, read_spec_file

    try:
        dur = parse_duration(duration) if duration else None
    except ValueError as e:
        console.print(f"[red][ERR] {e}[/red]")
        raise typer.Exit(2)

    if resume is not None:
        try:
            job = (manager.latest_resumable() if resume == RESUME_LATEST
                   else manager.load(resume))
        except (FileNotFoundError, ValueError) as e:
            console.print(f"[red][ERR] {e}[/red]")
            raise typer.Exit(1)
        if job is None:
            console.print("[red]No unfinished job to resume. See `suvari.py auto --jobs`.[/red]")
            raise typer.Exit(1)
        if job.status == "done":
            console.print(f"[yellow]Job {job.id} is already done.[/yellow] "
                          f"Report: {manager.job_dir(job.id) / job.report}")
            raise typer.Exit(1)
        if url or target or targets_file:
            console.print("[yellow]Ignoring target arguments: resuming the stored job.[/yellow]")
        # explicit budget flags extend/override the stored budget
        for k, v in (("duration", dur), ("max_requests", max_requests),
                     ("max_tokens", max_tokens), ("concurrency", concurrency),
                     ("rate_per_min", rate_per_min)):
            if v is not None:
                job.budget[k] = v
        manager.save(job)
    else:
        specs = ([url] if url else []) + [*target]
        try:
            if targets_file:
                specs += read_spec_file(targets_file)
            scope_specs = read_spec_file(scope_file) if scope_file else None
            if not specs:
                console.print("[red]No target given. Use URL, --target or --targets.[/red]")
                raise typer.Exit(2)
            job = manager.create(
                specs, scope_specs=scope_specs, extra_scope=allow_host,
                allow_large_scope=allow_large_scope,
                duration=dur if dur is not None else time_budget,
                max_requests=max_requests, max_tokens=max_tokens,
                max_steps=max_steps, rate_per_min=rate_per_min or 60,
                concurrency=concurrency or 1, dry_run=dry_run,
                provider=provider, model=model,
            )
        except (ScopeError, OSError) as e:
            console.print(f"[red][ERR] scope: {e}[/red]")
            raise typer.Exit(2)

    _run_job(manager, job)


def _run_job(manager, job) -> None:
    from rich.markup import escape
    from .auto.jobs import JobRunner, format_duration
    from .auto.session import build_llm

    eng = job.engine
    llm = None
    if not eng.get("dry_run"):
        try:
            llm = build_llm(eng.get("provider"), eng.get("model"))
        except RuntimeError as e:
            console.print(f"[red][ERR] {e}[/red]")
            raise typer.Exit(1)

    b = job.budget
    job_dir = manager.job_dir(job.id)
    engine_label = "deterministic (dry-run)" if eng.get("dry_run") else \
        f"{eng.get('provider')}/{eng.get('model') or 'default'}"
    console.print(f"[bold][JOB] {job.id}[/bold]  [dim]{job_dir}[/dim]")
    console.print(f"[bold][TGT] Targets:[/bold] {len(job.targets)}  "
                  f"[bold]Scope:[/bold] {', '.join(job.scope)}")
    console.print(f"[bold][MODE]  Engine:[/bold] {engine_label}")
    console.print(
        "[dim]budget: "
        + (format_duration(b["duration"]) if b.get("duration") else "no time limit")
        + f" / {b.get('max_requests') or '∞'} requests / {b.get('max_tokens') or '∞'} tokens"
        + f" · {b.get('max_steps')} steps per target · concurrency {b.get('concurrency')}"
        + f" · {b.get('rate_per_min')} req/min global · safe mode (GET only)[/dim]\n")

    def on_event(kind: str, msg: str) -> None:
        style = {"stop": "yellow", "target-skip": "yellow", "target-error": "red",
                 "target-end": "green"}.get(kind, "cyan")
        console.print(f"  [{style}]\\[{kind}][/{style}] {escape(msg)}")

    runner = JobRunner(job, manager, llm=llm, on_event=on_event)
    try:
        result = runner.run()
    except KeyboardInterrupt:
        console.print(f"[yellow]Aborted. Resume where it left off: "
                      f"python suvari.py auto --resume {job.id}[/yellow]")
        raise typer.Exit(130)

    c = result["counters"]
    color = {"done": "green", "paused": "yellow"}.get(result["status"], "red")
    console.print(f"\n[{color}]{result['status'].upper()}[/{color}] — {result['stop_reason']}")
    console.print(f"  targets {len(result['targets'])} · requests {c['requests']} · "
                  f"turns {c['turns']} · findings {c['findings']} · "
                  f"blocked {c['blocked']} · active {format_duration(c['elapsed'])}")
    for t in result["targets"]:
        console.print(f"  - {t['url']}: {t['status']} ({t['turns']} turns, "
                      f"{t['findings']} findings)")
    console.print(f"[bold][DOC] Report:[/bold] {result['report']}")
    if result["status"] != "done":
        console.print(f"[yellow]Resume where it left off: "
                      f"python suvari.py auto --resume {job.id}[/yellow]")
    _write_last_pointer(job_dir)


def _print_jobs(manager) -> None:
    from rich.table import Table
    from .auto.jobs import format_duration

    jobs = manager.list()
    if not jobs:
        console.print(f"[yellow]No jobs under {manager.root}[/yellow]")
        return
    t = Table(show_header=True, header_style="bold cyan")
    for col in ("ID", "Status", "Targets", "Active time", "Requests", "Findings", "Created"):
        t.add_column(col)
    from datetime import datetime
    for j in jobs:
        done = sum(1 for x in j.targets if x.status not in ("pending", "running", "paused"))
        t.add_row(j.id, j.status, f"{done}/{len(j.targets)}",
                  format_duration(j.counters.get("elapsed", 0)),
                  str(j.counters.get("requests", 0)),
                  str(j.counters.get("findings", 0)),
                  datetime.fromtimestamp(j.created_at).strftime("%Y-%m-%d %H:%M"))
    console.print(t)


def _auto_legacy(url, output, provider, model, max_steps, time_budget,
                 rate_per_min, allow_host, resume, dry_run,
                 max_tokens=None) -> None:
    """Original single-target engine writing into one workspace directory."""
    from .auto.session import run_auto

    root = output
    root.mkdir(parents=True, exist_ok=True)
    console.print(f"[bold][TGT] Target:[/bold] {url}")
    engine_label = "deterministic (dry-run)" if dry_run else f"{provider}/{model or 'default'}"
    console.print(f"[bold][MODE]  Engine:[/bold] {engine_label}")
    console.print(f"[bold][DIR] Output:[/bold] {root}")
    console.print(f"[dim]budget: {max_steps} steps / {time_budget:.0f}s / {rate_per_min} req-min · safe mode[/dim]\n")

    try:
        result = run_auto(
            url, root, provider=provider, model=model,
            max_steps=max_steps, time_budget=time_budget, max_tokens=max_tokens,
            rate_per_min=rate_per_min,
            resume=resume, dry_run=dry_run, allow_hosts=allow_host,
        )
    except RuntimeError as e:
        console.print(f"[red][ERR] {e}[/red]")
        raise typer.Exit(1)

    findings = result.get("findings", [])
    console.print(f"[green]Done.[/green] {result['turns']} turns, {len(findings)} findings "
                  f"({result.get('stop_reason','')})")
    tech = result.get("detected_tech") or []
    if tech:
        n_tech = sum(1 for h in result.get("hypotheses", [])
                     if str(h.get("rationale", "")).startswith("tech-aware"))
        console.print(f"[dim]detected: {', '.join(tech)} · {n_tech} tech-aware vectors[/dim]")
    for f in findings:
        console.print(f"  [[{f['severity']}]] {f['title']} — {f['target']}  [dim]{f['evidence']}[/dim]")
    console.print(f"[bold][DOC] Report:[/bold] {result['report']}")
    from .auto.usage import format_summary
    console.print(f"[dim]{format_summary(result.get('usage') or {})}[/dim]")
    _write_last_pointer(root)


def normalize_auto_argv(argv: list[str]) -> list[str]:
    """Let ``--resume`` work both bare (legacy flag) and with a job id.

    Typer options cannot take an optional value, so a bare ``--resume`` (end
    of line, followed by another option, or followed by a URL/target rather
    than a job id) gets the ``latest`` sentinel inserted.
    """
    if "auto" not in argv:
        return argv
    out = argv[:]  # (`list` is shadowed by the `list` command below)
    i = out.index("auto") + 1
    while i < len(out):
        if out[i] == "--resume":
            nxt = out[i + 1] if i + 1 < len(out) else None
            if nxt is None or nxt.startswith("-") or not _looks_like_job_id(nxt):
                out.insert(i + 1, RESUME_LATEST)
            i += 2
            continue
        i += 1
    return out


def _looks_like_job_id(s: str) -> bool:
    import re
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", s)) and not re.fullmatch(r"[0-9]+", s)


def main() -> None:
    import sys
    sys.argv[1:] = normalize_auto_argv(sys.argv[1:])
    app()


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
