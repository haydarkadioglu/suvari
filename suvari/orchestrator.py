"""
Orchestrator — main pipeline controller.
Inspired by Shannon's multi-agent pipeline + LuaN1aoAgent's P-E-R framework.
"""

from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from .llm import LLMClient
from .workspace import Workspace
from .tools.runner import ToolRunner
from .agents.recon import ReconAgent
from .agents.scanner import ScannerAgent
from .agents.analyzer import AnalyzerAgent
from .agents.exploiter import ExploiterAgent
from .report import ReportGenerator

console = Console()


class SuvariOrchestrator:
    """Main orchestrator — manages the pipeline."""

    PHASES = [
        ("recon", "🌐 Reconnaissance", "Target analysis"),
        ("scan", "🔍 Vulnerability Scan", "Security scanning"),
        ("analyze", "🧠 AI Analysis", "LLM-powered analysis"),
        ("exploit", "💥 Exploitation", "Proof of concept"),
        ("report", "📄 Report", "Report generation"),
    ]

    def __init__(
        self,
        target_url: str,
        workspace: Workspace,
        provider: str = "openai",
        model: Optional[str] = None,
        recon_only: bool = False,
        fast: bool = False,
        verbose: bool = False,
    ):
        self.target_url = target_url
        self.ws = workspace
        self.recon_only = recon_only
        self.fast = fast
        self.verbose = verbose

        self.llm = LLMClient(provider=provider, model=model)
        self.tools = ToolRunner(verbose=verbose)

        self.recon_agent = ReconAgent("recon", self.llm, self.ws, self.tools, verbose)
        self.scanner_agent = ScannerAgent("scanner", self.llm, self.ws, self.tools, verbose)
        self.analyzer_agent = AnalyzerAgent("analyzer", self.llm, self.ws, self.tools, verbose)
        self.exploiter_agent = ExploiterAgent("exploiter", self.llm, self.ws, self.tools, verbose)
        self.reporter = ReportGenerator(self.ws, self.target_url)

        self.context = {"target_url": target_url, "fast": fast}

    def run(self):
        """Start the pipeline."""

        avail = self.tools.available_tools()
        console.print(f"[bold]🧰 Available Tools:[/bold] {', '.join(avail.keys()) or '(none)'}")
        if not avail:
            console.print("[yellow]⚠️ No Kali tools found. Only curl and AI analysis will work.[/yellow]")
        console.print("")

        phases = self.PHASES
        if self.recon_only:
            phases = [self.PHASES[0]]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:

            for phase_id, phase_name, phase_desc in phases:
                task = progress.add_task(f"{phase_name} — {phase_desc}", total=None)
                try:
                    self._run_phase(phase_id)
                except Exception as e:
                    console.print(f"\n[red]❌ {phase_name} error: {e}[/red]")
                    self.context["error"] = str(e)
                    break
                finally:
                    progress.remove_task(task)

        console.print("\n[bold green]✅ Scan complete![/bold green]")
        report_path = self.ws.path / "report.md"
        console.print(f"[bold]📁 Report:[/bold] {report_path}")

        analysis = self.context.get("analysis", {})
        summary = analysis.get("summary", {})
        if summary.get("total", 0) > 0:
            console.print(f"\n[red]⚠️ {summary['total']} vulnerabilities found![/red]")
            console.print(f"  Critical: {summary.get('critical', 0)} | High: {summary.get('high', 0)} | Medium: {summary.get('medium', 0)}")
        else:
            console.print("[green]✅ No significant vulnerabilities detected.[/green]")

    def _run_phase(self, phase_id: str):
        """Run a single pipeline phase."""

        if phase_id == "recon":
            console.print(f"  🎯 {self.target_url}")
            self.context["recon_results"] = self.recon_agent.run(self.context)

        elif phase_id == "scan":
            self.context["scan_results"] = self.scanner_agent.run(self.context)

        elif phase_id == "analyze":
            self.context["analysis"] = self.analyzer_agent.run(self.context)

        elif phase_id == "exploit":
            self.context["exploit_results"] = self.exploiter_agent.run(self.context)

        elif phase_id == "report":
            report = self.reporter.generate(self.context)
            console.print(f"\n📄 Report generated ({len(report)} chars)")
