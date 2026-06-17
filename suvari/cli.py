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
    help="🐎 Suvari — AI-Powered Black-Box Web Pentester",
    no_args_is_help=True,
)


def banner():
    console.print(Panel.fit(
        "[bold yellow]🐎 Suvari[/bold yellow] — AI Cavalry\n"
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
    """⚙️  Interactive setup — provider, model, API key"""
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
    source: Optional[Path] = typer.Option(None, "--source", "-r", help="Source code directory (white-box mode)"),
):
    """🔍 Scan target URL — recon → vulnerability scan → analysis → report"""
    banner()
    provider, model = _resolve_provider(provider, model)
    scan_mode = ScanMode.from_str(mode)
    ws = Workspace(name or url, output)
    console.print(f"[bold]🎯 Target:[/bold] {url}")
    console.print(f"[bold]🤖 Model:[/bold] {provider}/{model or 'default'}")
    console.print(f"[bold]⚙️  Mode:[/bold] {scan_mode}")
    if source:
        console.print(f"[bold]📁 Source:[/bold] {source} (white-box mode)")
    console.print(f"[bold]📁 Output:[/bold] {ws.path}\n")
    orchestrator = SuvariOrchestrator(
        target_url=url,
        workspace=ws,
        provider=provider,
        model=model,
        recon_only=recon_only,
        fast=fast,
        verbose=verbose,
        scan_mode=scan_mode,
        source_dir=source,
    )
    orchestrator.run()


@app.command()
def recon(
    url: str = typer.Argument(..., help="Target URL"),
    provider: str = typer.Option("openai", "--provider", "-p"),
    model: Optional[str] = typer.Option(None, "--model", "-m"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """🌐 Reconnaissance only (quick)"""
    banner()
    provider, model = _resolve_provider(provider, model)
    ws = Workspace(f"recon-{url}", output)
    console.print(f"[bold]🎯 Target:[/bold] {url}")
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
    """📄 Show report from a previous scan"""
    banner()
    report_path = path / "report.md"
    if not report_path.exists():
        console.print("[red]❌ report.md not found in that directory[/red]")
        raise typer.Exit(1)
    console.print(f"[bold]📄 Report:[/bold] {report_path}")
    console.print(report_path.read_text())


@app.command()
def list():
    """📋 List previous scans"""
    banner()
    output_dir = Path("output")
    if not output_dir.exists():
        console.print("[yellow]No scans found yet.[/yellow]")
        return
    for d in sorted(output_dir.iterdir()):
        if d.is_dir():
            report_file = d / "report.md"
            status = "✅" if report_file.exists() else "🔄"
            console.print(f"  {status} {d.name}")
