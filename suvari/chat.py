"""
Chat — interactive pentesting conversation.
Like talking to a security expert. Give commands naturally.
"""

import time
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from .llm import LLMClient
from .workspace import Workspace
from .orchestrator import SuvariOrchestrator
from .tools.runner import ToolRunner
from .config import load_config
from .mode import ScanMode

console = Console()

SYSTEM_PROMPT = """You are Suvari, an AI-powered penetration testing assistant. You help users test web applications and servers for security vulnerabilities.

You have access to:
- Scanning: full pipeline (recon → scan → analyze → exploit → report)
- Tools: nmap, whatweb, nuclei, nikto, gobuster, ffuf, sqlmap, wpscan, curl, httpx
- Modes: auto (silent), guided (ask me), interactive (chat)
- Server mode: all ports + services
- White-box mode: with source code

When the user asks you to scan something:
1. Acknowledge the target
2. Run the scan
3. Summarize findings
4. Ask what to do next

If they ask about a specific vulnerability or technique:
- Explain it briefly
- Offer to test it
- Suggest related checks

Keep responses concise and actionable.
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
            "[bold yellow]🐎 Suvari Chat[/bold yellow]\n"
            "[dim]AI Pentester Assistant — type 'help' for commands[/dim]",
            border_style="yellow"
        ))
        console.print("  Try: [bold]scan https://example.com[/bold]")
        console.print("  Try: [bold]check /api on juice-shop[/bold]")
        console.print("  Try: [bold]what tools do you have?[/bold]")
        console.print("  Type [bold]exit[/bold] to quit\n")

        while True:
            try:
                user_input = input("  \033[1;33mYou\033[0m > ").strip()
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

            except KeyboardInterrupt:
                console.print("\n[yellow]Goodbye![/yellow]")
                break
            except EOFError:
                break

    def _show_help(self):
        """Show available commands."""
        console.print("""
  [bold]Commands:[/bold]
    scan <url>              Run full scan (recon → analysis → report)
    scan <url> --fast       Quick scan
    scan <url> -s           Server scan (all ports)
    scan <url> -r <path>    White-box scan (with source code)
    
    recon <url>             Reconnaissance only
    
    check <endpoint>        Quick check on specific endpoint
    nmap <host>             Run nmap
    whatweb <url>           Run whatweb
    
    help                    Show this message
    history                 Show scan history
    report                  Show last scan report
    
    exit / quit             Exit chat
        """)

    def _handle_input(self, text: str):
        """Process user input and execute appropriate action."""
        text_lower = text.lower().strip()

        # Scan commands
        if text_lower.startswith("scan ") or text_lower.startswith("scan "):
            self._cmd_scan(text)
            return

        if text_lower.startswith("recon "):
            self._cmd_recon(text)
            return

        if text_lower == "report" and self.last_scan_dir:
            self._show_report()
            return

        if text_lower in ("history", "list"):
            self._list_scans()
            return

        if text_lower.startswith("check "):
            self._cmd_check(text)
            return

        # For everything else, let the LLM respond
        self._llm_chat()

    def _cmd_scan(self, text: str):
        """Parse and run a scan command."""
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
            console.print("[red]Please provide a URL. Example: scan https://example.com[/red]")
            return

        # Add http:// if missing
        if not url.startswith("http"):
            url = "https://" + url

        console.print(f"\n[bold] Scanning {url}...[/bold]")
        if fast:
            console.print("  Fast mode")
        if server:
            console.print("  Server mode (all ports)")
        if source:
            console.print(f"  White-box: {source}")

        # Run orchestrator
        ws = Workspace(url)
        orchestrator = SuvariOrchestrator(
            target_url=url,
            workspace=ws,
            recon_only=False,
            fast=fast,
            verbose=False,
            scan_mode=mode,
            source_dir=source,
            server_scan=server,
        )
        orchestrator.run()
        self.last_scan_dir = ws.path

        # Brief summary
        analysis = orchestrator.context.get("analysis", {})
        summary = analysis.get("summary", {})
        total = summary.get("total", 0)
        if total > 0:
            vulns = analysis.get("vulnerabilities", [])[:3]
            for v in vulns:
                console.print(f"  [{v.get('severity','?')}] {v.get('type','?')} — {v.get('location','')}")
            if len(vulns) < total:
                console.print(f"  ... and {total - len(vulns)} more findings")

        self.history.append({"role": "assistant", "content": f"Scan complete for {url}. Found {total} findings. Report at {ws.path / 'report.md'}"})

    def _cmd_recon(self, text: str):
        """Run recon only."""
        url = text.split()[-1]
        if not url.startswith("http"):
            url = "https://" + url
        console.print(f"\n[bold] Reconnaissance: {url}...[/bold]")

        from .agents.recon import ReconAgent
        ws = Workspace(f"recon-{url.strip('/').split('/')[-1]}")
        llm = self.llm
        tr = self.tools
        agent = ReconAgent("recon", llm, ws, tr)
        results = agent.run({"target_url": url})
        console.print(f"\n[green]Recon complete. Output: {ws.path}[/green]")
        self.history.append({"role": "assistant", "content": f"Recon complete for {url}"})

    def _cmd_check(self, text: str):
        """Quick check on a specific endpoint."""
        parts = text.split()
        if len(parts) < 2:
            console.print("[red]Specify what to check. Example: check /api[/red]")
            return
        endpoint = parts[1]
        url = f"{self._get_base_url()}{endpoint}" if self._get_base_url() else endpoint

        console.print(f"\n[bold] Checking {endpoint}...[/bold]")
        output = self.tools.run(["curl", "-sI", url, "--max-time", "10"], timeout=15)
        console.print(output[:500] if output else "(no response)")
        self.history.append({"role": "assistant", "content": f"Check results for {endpoint}"})

    def _get_base_url(self) -> str:
        """Try to get the base URL from chat history."""
        for msg in reversed(self.history):
            if msg["role"] == "assistant" and "Scan complete for" in msg.get("content", ""):
                parts = msg["content"].split()
                for p in parts:
                    if p.startswith("http"):
                        return p.rstrip(".")
        return ""

    def _show_report(self):
        """Show the last scan report."""
        if not self.last_scan_dir:
            console.print("[red]No scan results yet. Run a scan first.[/red]")
            return
        report_file = self.last_scan_dir / "report.md"
        if report_file.exists():
            console.print(Markdown(report_file.read_text()[:2000]))
        else:
            console.print("[red]Report not found.[/red]")

    def _list_scans(self):
        """List previous scans."""
        from pathlib import Path
        output_dir = Path("output")
        if not output_dir.exists():
            console.print("[yellow]No scans found.[/yellow]")
            return
        for d in sorted(output_dir.iterdir()):
            if d.is_dir():
                report = d / "report.md"
                status = "✅" if report.exists() else "🔄"
                console.print(f"  {status} {d.name}")

    def _llm_chat(self):
        """Let the LLM respond to general questions."""
        console.print("  \033[0;32mSuvari\033[0m > ", end="")
        try:
            response = self.llm.chat(
                messages=self.history[-5:],
                temperature=0.7,
                max_tokens=512,
            )
            console.print(response)
            self.history.append({"role": "assistant", "content": response})
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
