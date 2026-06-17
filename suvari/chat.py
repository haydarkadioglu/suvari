"""
Chat — interactive pentesting conversation.
Like talking to a security expert. Give commands naturally.
"""

from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.prompt import Prompt
from rich.rule import Rule
from .llm import LLMClient
from .workspace import Workspace
from .orchestrator import SuvariOrchestrator
from .tools.runner import ToolRunner
from .config import load_config
from .mode import ScanMode

console = Console()

SYSTEM_PROMPT = """You are Suvari, an AI-powered penetration testing assistant. You help users test web applications and servers for security vulnerabilities.

You have access to:
- Scanning: full pipeline (recon -> scan -> analyze -> exploit -> report)
- Tools: nmap, whatweb, nuclei, nikto, gobuster, ffuf, sqlmap, wpscan, curl, httpx
- Modes: auto (silent), guided (ask me), interactive (chat)
- Server mode: all ports + services
- White-box mode: with source code

When the user asks you to scan something:
1. Acknowledge the target briefly
2. Explain what you'll check in 1-2 sentences
3. Wait for the scan to complete
4. Summarize findings

Keep responses concise and actionable.
Respond in the same language as the user.
"""


class ChatSession:
    """Interactive pentesting chat session."""

    def __init__(self):
        cfg = load_config()
        provider = cfg.get("provider", "deepseek")
        model = cfg.get("model", "deepseek-chat")
        self.llm = LLMClient(provider=provider, model=model)
        self.tools = ToolRunner()
        self.history = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.last_scan_dir = None

    def run(self):
        """Start the chat loop."""
        console.print(Panel.fit(
            "[bold yellow][SUVARI] Suvari Chat[/bold yellow]\n"
            "[dim]AI Pentester Assistant — write naturally, I'll figure it out[/dim]",
            border_style="yellow"
        ))
        console.print("  [dim]Examples:[/dim]")
        console.print("    [bold]scan https://example.com[/bold]")
        console.print("    [bold]check /api on that site[/bold]")
        console.print("    [bold]show the report[/bold]")
        console.print("    [bold]exit[/bold] to quit\n")

        while True:
            try:
                user_input = Prompt.ask("[bold yellow]You[/bold yellow]").strip()
                if not user_input:
                    continue
                if user_input.lower() in ("exit", "quit", "q"):
                    console.print("[yellow]Goodbye![/yellow]")
                    break
                if user_input.lower() == "help":
                    self._show_help()
                    continue

                self.history.append({"role": "user", "content": user_input})
                self._handle_input(user_input)

            except (KeyboardInterrupt, EOFError):
                console.print("\n[yellow]Goodbye![/yellow]")
                break

    def _show_help(self):
        from rich.table import Table
        t = Table(show_header=False, box=None)
        t.add_column("Command", style="bold cyan")
        t.add_column("Description")
        t.add_row("scan <url>", "Full scan: recon -> analysis -> report")
        t.add_row("scan <url> -s", "Server scan (all ports)")
        t.add_row("scan <url> -r ./src", "White-box scan")
        t.add_row("recon <url>", "Reconnaissance only")
        t.add_row("check <path>", "Quick endpoint check")
        t.add_row("report", "Show last scan report")
        t.add_row("history", "List previous scans")
        t.add_row("exit", "Quit chat")
        console.print(t)

    def _handle_input(self, text: str):
        t = text.strip().lower()

        if t.startswith("scan "):
            self._cmd_scan(text)
            return
        if t.startswith("recon "):
            self._cmd_recon(text)
            return
        if t == "report" and self.last_scan_dir:
            self._show_report()
            return
        if t in ("history", "scans", "list"):
            self._list_scans()
            return
        if t.startswith("check "):
            self._cmd_check(text)
            return

        # General chat — let LLM respond
        console.print()
        try:
            response = self.llm.chat(
                messages=self.history[-6:],
                temperature=0.7,
                max_tokens=512,
            )
            console.print(response)
            self.history.append({"role": "assistant", "content": response})
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

    def _cmd_scan(self, text: str):
        """Parse and run a scan from chat input."""
        parts = text.split()
        url = None
        fast = False
        server = False
        source = None
        mode = ScanMode.GUIDED

        i = 1
        while i < len(parts):
            p = parts[i]
            if p.startswith("http://") or p.startswith("https://") or "." in p:
                url = p
            elif p in ("--fast", "-f"):
                fast = True
            elif p in ("-s", "--server"):
                server = True
            elif p in ("-r", "--source") and i + 1 < len(parts):
                source = parts[i + 1]
                i += 1
            elif p in ("-M", "--mode") and i + 1 < len(parts):
                mode = ScanMode.from_str(parts[i + 1])
                i += 1
            i += 1

        if not url:
            # Try to extract URL more aggressively
            for p in parts[1:]:
                if not p.startswith("-"):
                    url = p
                    break

        if not url:
            console.print("[red]Please provide a URL. Example: scan https://example.com[/red]")
            return

        if not url.startswith("http"):
            url = "https://" + url

        # Quick AI acknowledgment
        console.print(f"[dim]Starting scan: {url}[/dim]")
        if fast:
            console.print("[dim]Fast mode[/dim]")
        if server:
            console.print("[dim]Server mode (all ports)[/dim]")
        console.print()

        # Run orchestrator
        ws = Workspace(url)
        orchestrator = SuvariOrchestrator(
            target_url=url,
            workspace=ws,
            recon_only=False,
            fast=fast,
            verbose=False,
            scan_mode=ScanMode.GUIDED,
            parallel=3,
            source_dir=source,
            server_scan=server,
        )
        orchestrator.run()
        self.last_scan_dir = ws.path

        # After scan: summary
        analysis = orchestrator.context.get("analysis", {})
        findings = analysis.get("vulnerabilities", [])
        summary = analysis.get("summary", {})

        console.print(Rule(style="dim"))
        if findings:
            console.print(f"[bold red]Found {len(findings)} issues:[/bold red]")
            for v in findings[:5]:
                sev = v.get("severity", "?")
                icon = {"CRITICAL": "[CRIT]", "HIGH": "[WARN]", "MEDIUM": "[INFO]", "LOW": "[INFO]"}.get(sev, "•")
                console.print(f"  {icon} [{sev}] {v.get('type','?')} — {v.get('location','')}")
            if len(findings) > 5:
                console.print(f"  ... and {len(findings) - 5} more")
        else:
            console.print("[green]No significant issues found.[/green]")

        console.print(f"[dim]Report: {ws.path / 'report.md'}[/dim]")
        console.print()
        self.history.append({
            "role": "assistant",
            "content": f"Scan complete for {url}. Found {summary.get('total', 0)} findings: "
                       f"{', '.join(f['type'] for f in findings[:3])}"
        })

    def _cmd_recon(self, text: str):
        """Run recon only."""
        url = text.split()[-1]
        if not url.startswith("http"):
            url = "https://" + url

        console.print(f"[dim]Reconnaissance: {url}[/dim]")
        from .agents.recon import ReconAgent
        ws = Workspace(f"recon-{url.strip('/').split('/')[-1]}")
        agent = ReconAgent("recon", self.llm, ws, self.tools)
        results = agent.run({"target_url": url})
        console.print(f"[green]Recon complete.[/green] [dim]{ws.path}[/dim]")
        self.history.append({"role": "assistant", "content": f"Recon complete for {url}"})

    def _cmd_check(self, text: str):
        """Quick check on a specific endpoint."""
        parts = text.split()
        if len(parts) < 2:
            console.print("[red]Specify endpoint. Example: check /api[/red]")
            return

        endpoint = parts[1]
        base = self._get_last_target()
        url = f"{base}{endpoint}" if base else endpoint

        console.print(f"[dim]Checking: {url}[/dim]")
        out = self.tools.run(["curl", "-sI", url, "--max-time", "10"], timeout=15)
        lines = out[:500].split("\n")
        for line in lines[:10]:
            console.print(f"  {line}")
        self.history.append({"role": "assistant", "content": f"Check results for {endpoint}"})

    def _get_last_target(self) -> str:
        """Get the last scanned URL from history."""
        for msg in reversed(self.history):
            if msg["role"] == "assistant" and "Scan complete" in msg.get("content", ""):
                for word in msg["content"].split():
                    if word.startswith("http"):
                        return word.rstrip(".")
        return ""

    def _show_report(self):
        """Show last scan report."""
        if not self.last_scan_dir:
            console.print("[red]No scan results yet.[/red]")
            return
        report = self.last_scan_dir / "report.md"
        if report.exists():
            console.print(Markdown(report.read_text()[:2500]))
        else:
            console.print("[red]Report not found.[/red]")

    def _list_scans(self):
        """List previous scan directories."""
        p = Path("output")
        if not p.exists():
            console.print("[yellow]No scans yet.[/yellow]")
            return
        for d in sorted(p.iterdir()):
            if d.is_dir():
                r = d / "report.md"
                s = "[OK]" if r.exists() else "[RESUME]"
                console.print(f"  {s} {d.name}")
