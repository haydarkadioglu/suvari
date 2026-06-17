"""
Orchestrator — main pipeline controller with P-E-R integration + checkpoint/resume.
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
from .state import PipelineState
from .core import Planner, Reflector
from .prompt_loader import PromptLoader
from .scan_logger import ScanLogger
from .mode import ScanMode, ask_user, show_finding, ask_suggestions, show_recon_summary

console = Console()


class SuvariOrchestrator:
    """Main orchestrator — manages the pipeline with P-E-R and resume support."""

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
        scan_mode: ScanMode = ScanMode.GUIDED,
        source_dir: Optional[Path] = None,
        server_scan: bool = False,
    ):
        self.target_url = target_url
        self.ws = workspace
        self.recon_only = recon_only
        self.fast = fast
        self.verbose = verbose
        self.mode = scan_mode
        self.source_dir = source_dir
        self.server_scan = server_scan

        self.state = PipelineState(workspace.path)
        self.logger = ScanLogger(workspace.path)
        self.logger.info("suvari", f"Scan started: {target_url} (provider={provider}, fast={fast})")
        self.llm = LLMClient(provider=provider, model=model)
        self.tools = ToolRunner(verbose=verbose)
        self.prompts = PromptLoader(target_url, fast)

        # P-E-R components
        self.planner = Planner(self.llm, self.tools, self.prompts)
        self.reflector = Reflector(self.llm)

        # Agents (executors)
        self.recon_agent = ReconAgent("recon", self.llm, self.ws, self.tools, verbose)
        self.scanner_agent = ScannerAgent("scanner", self.llm, self.ws, self.tools, verbose)
        self.analyzer_agent = AnalyzerAgent("analyzer", self.llm, self.ws, self.tools, verbose)
        self.exploiter_agent = ExploiterAgent("exploiter", self.llm, self.ws, self.tools, verbose)
        self.reporter = ReportGenerator(self.ws, self.target_url)

        self.context = {"target_url": target_url, "fast": fast, "source_dir": source_dir, "mode": scan_mode, "server_scan": server_scan}

    def run(self):
        """Start (or resume) the pipeline with P-E-R adaptive execution."""

        # Check if resuming
        is_resume = self.state.has_partial_run()
        if is_resume:
            done = ", ".join(self.state.completed)
            console.print(f"[yellow]🔄 Resuming scan — already completed: {done}[/yellow]")

        avail = self.tools.available_tools()
        console.print(f"[bold]🧰 Available Tools:[/bold] {', '.join(avail.keys()) or '(none)'}")
        if not avail:
            console.print("[yellow]⚠️ No Kali tools found. Only curl and AI analysis will work.[/yellow]")
        console.print("")

        # Determine phases to run
        phases = self.PHASES
        if self.recon_only:
            phases = [self.PHASES[0]]

        # Skip completed phases on resume
        if is_resume:
            remaining = self.state.resume_from(phases)
            if not remaining:
                console.print("[green]✅ All phases already completed! Showing report.[/green]")
                self._show_results()
                return
            skipped = [p[1] for p in phases if p[0] in self.state.completed]
            if skipped:
                console.print(f"[dim]⏭️ Skipping completed: {', '.join(skipped)}[/dim]")
            phases = remaining

        # Initialize state if new scan
        if not is_resume:
            self.state.start(self.target_url)

        # Run phases with P-E-R
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:

            for phase_id, phase_name, phase_desc in phases:
                task = progress.add_task(f"{phase_name} — {phase_desc}", total=None)
                self.state.phase_start(phase_id)

                try:
                    # PLAN: Planner decides approach for this phase
                    plan = self.planner.decide(
                        phase=phase_id,
                        completed=self.state.completed,
                        last_results=self.context,
                    )
                    action = plan.get("next_action", phase_id)

                    if self.verbose:
                        console.print(f"\n[dim]  📋 Plan: {plan.get('reasoning', '')[:100]}[/dim]")

                    # EXECUTE: Run the phase
                    self._run_phase(phase_id)

                    # REFLECT: Reflector analyzes the results
                    if phase_id != "report":
                        phase_output = self._get_phase_output(phase_id)
                        reflection = self.reflector.analyze(
                            last_action=phase_id,
                            tool=action,
                            output=phase_output,
                            target_url=self.target_url,
                        )

                        # Feed findings back to planner
                        for finding in reflection.get("findings", []):
                            self.planner.add_knowledge(finding)

                        if self.verbose:
                            ref_success = reflection.get("success", False)
                            ref_findings = len(reflection.get("findings", []))
                            console.print(f"  [dim]🔍 Reflection: {'✅' if ref_success else '⚠️'} {ref_findings} findings[/dim]")

                    self.state.phase_complete(phase_id)

                except Exception as e:
                    console.print(f"\n[red]❌ {phase_name} error: {e}[/red]")
                    self.context["error"] = str(e)
                    self.state.set_error(str(e))
                    break
                finally:
                    progress.remove_task(task)

        self._show_results()

    def _get_phase_output(self, phase_id: str) -> str:
        """Get combined output from a phase for reflection."""
        return self.ws.get_phase_output(phase_id)[:2000]

    def _show_results(self):
        """Show final results with timing."""
        console.print("\n[bold green]✅ Scan complete![/bold green]")
        report_path = self.ws.path / "report.md"
        console.print(f"[bold]📁 Report:[/bold] {report_path}")

        # Show phase timing
        recon_time = self.context.get("recon_results", {}).get("_recon_time", "")
        scan_time = self.context.get("scan_results", {}).get("_total_time", "")
        if recon_time or scan_time:
            console.print(f"[dim]  Recon: {recon_time} | Scan: {scan_time}[/dim]")

        analysis = self.context.get("analysis", {})
        summary = analysis.get("summary", {})
        if summary.get("total", 0) > 0:
            console.print(f"\n[red]⚠️ {summary['total']} vulnerabilities found![/red]")
            console.print(f"  Critical: {summary.get('critical', 0)} | High: {summary.get('high', 0)} | Medium: {summary.get('medium', 0)}")
        else:
            console.print("[green]✅ No significant vulnerabilities detected.[/green]")

    def _run_phase(self, phase_id: str):
        """Run a single pipeline phase."""
        self.logger.info("phase", f"Starting: {phase_id}")

        if phase_id == "recon":
            console.print(f"  🎯 {self.target_url}")
            self.context["recon_results"] = self.recon_agent.run(self.context)
            self.logger.info("phase", "Recon complete")

            # Ask user for suggestions (guided/interactive mode)
            if self.mode.suggestions_enabled:
                show_recon_summary(self.context.get("recon_results", {}))
                suggestion = ask_suggestions(
                    "Any areas to focus on?",
                    "e.g.: check /api, try SQL injection on login, look for JWT tokens"
                )
                if suggestion:
                    self.context["user_suggestions"] = suggestion
                    self.logger.info("phase", f"User suggestion: {suggestion}")

        elif phase_id == "scan":
            self.context["scan_results"] = self.scanner_agent.run(self.context)
            scan_ok = self.context.get("scan_results", {})
            tools_run = [k for k in scan_ok if not k.endswith("_time") and not k.endswith("_status") and not k.startswith("_")]
            self.logger.info("phase", f"Scan complete: {tools_run}")

        elif phase_id == "analyze":
            # Include user suggestions in analysis context
            if self.context.get("user_suggestions"):
                self.context["analysis_context"] = f"User specifically asked to check: {self.context['user_suggestions']}"

            self.context["analysis"] = self.analyzer_agent.run(self.context)
            summary = self.context.get("analysis", {}).get("summary", {})
            vulnerabilities = self.context.get("analysis", {}).get("vulnerabilities", [])
            self.logger.info("phase", f"Analysis complete: {summary.get('total', 0)} findings")

            # Show live findings
            if vulnerabilities:
                print(f"\n  {'='*50}")
                print(f"  📋 FINDINGS ({len(vulnerabilities)})")
                for v in vulnerabilities:
                    show_finding(v)
                print(f"  {'='*50}\n")

            # Ask user for suggestions after analysis
            if self.mode.suggestions_enabled:
                suggestion = ask_suggestions(
                    "Any specific exploit to try?",
                    "e.g.: try sqlmap on the search endpoint, check if admin:admin works"
                )
                if suggestion:
                    self.context["user_suggestions"] = (self.context.get("user_suggestions", "")
                                                        + "\n" + suggestion)
                    self.logger.info("phase", f"User exploit suggestion: {suggestion}")

                if not ask_user("Proceed with exploitation?", default=True):
                    self.logger.info("phase", "User declined exploitation")
                    return

        elif phase_id == "exploit":
            self.context["exploit_results"] = self.exploiter_agent.run(self.context)

        elif phase_id == "report":
            report = self.reporter.generate(self.context)
            console.print(f"\n📄 Report generated ({len(report)} chars)")
            self.logger.info("phase", "Report generated")
