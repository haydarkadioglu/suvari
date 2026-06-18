"""
Chat — interactive pentesting conversation with P-E-R (Planner-Executor-Reflector).
AI decides what tools to run, executes them, and analyzes results.
"""

from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from .llm import LLMClient
from .workspace import Workspace
from .tools.runner import ToolRunner
from .mode import ScanMode
from .config import load_config
import re, shlex

console = Console()

SYSTEM_PROMPT = """You are Suvari, an AI-powered pentesting assistant. You have access to security tools.

HOW TO USE TOOLS:
If you need to run a command, write it in a code block with language "tool":
```tool
nmap -F example.com
```

After you run a command, you'll see the output. Then you can run more commands or give a final response.

RULES:
- Be concise. Final response: 2-3 sentences.
- For scan results: list findings briefly.
- For CTF: suggest specific commands.
- For report queries: say "read the report" and the system will show it.
- Never say "I'll check" or describe what you'd do - just do it with tools.
- Respond in the same language as the user.
"""


class ChatSession:
    """Interactive pentesting chat with tool execution."""

    def __init__(self):
        cfg = load_config()
        self.llm = LLMClient(provider=cfg.get("provider", "deepseek"), model=cfg.get("model"))
        self.tools = ToolRunner()
        self.history = []
        self.last_scan_dir: Optional[Path] = None
        self.last_scan_url: Optional[str] = None

    def run(self):
        """Main chat loop."""
        console.print("[bold][SUVARI] — AI Pentester Assistant[/bold]")
        console.print("Type 'help' for commands, 'exit' to quit.\n")

        while True:
            try:
                text = Prompt.ask("You")
            except (EOFError, KeyboardInterrupt):
                console.print("\nGoodbye!")
                break

            if text.strip().lower() in ("exit", "quit", "q"):
                console.print("Goodbye!")
                break

            if text.strip().lower() == "help":
                self._show_help()
                continue

            self._handle_input(text)

    def _show_help(self):
        """Show available commands."""
        t = Table(show_header=False, border_style="dim")
        t.add_row("scan <url>", "Full security scan")
        t.add_row("recon <url>", "Quick reconnaissance")
        t.add_row("report", "Show last scan report")
        t.add_row("history", "List previous scans")
        t.add_row("exit", "Quit chat")
        console.print(t)
        console.print("\nOr just describe what you want to check:")
        console.print('  "check CORS on example.com"')
        console.print('  "test SQL injection on /search"')
        console.print('  "find subdomains for example.com"')
        console.print('  "binary var, buffer overflow"')

    def _handle_input(self, text: str):
        """Route input based on keywords or use P-E-R loop."""
        t = text.strip().lower()

        if t.startswith("scan "):
            self._cmd_scan(text)
            return
        if t.startswith("recon "):
            self._cmd_recon(text)
            return
        if any(kw in t for kw in ["rapor", "report", "bulgular", "show results", "findings"]):
            if self.last_scan_dir:
                self._show_report()
                return
        if t in ("history", "scans", "list"):
            self._list_scans()
            return

        # Everything else goes through P-E-R
        self._per_loop(text)

    def _per_loop(self, user_input: str, max_rounds: int = 3):
        """Planner-Executor-Reflector loop. AI decides, runs tools, analyzes."""
        self.history.append({"role": "user", "content": user_input})

        avail = ", ".join(sorted(self.tools.available_tools().keys()))
        context = f"Available tools: {avail}"

        for turn in range(max_rounds):
            messages = [{"role": "system", "content": SYSTEM_PROMPT + "\n\n" + context}]
            messages += self.history[-10:]

            response = self.llm.chat(messages=messages, temperature=0.3, max_tokens=1024, stream=True)

            commands = self._extract_tool_commands(response)

            if not commands:
                self.history.append({"role": "assistant", "content": response})
                return

            # Execute each command
            results = []
            for cmd in commands:
                console.print(f"  $ {cmd}")
                try:
                    parts = shlex.split(cmd)
                    output = self.tools.run(parts, timeout=60)
                except Exception as e:
                    output = f"(error: {e})"
                preview = output[:500].replace("\n", "\n  ")
                console.print(f"  {preview}")
                results.append(f"Command: {cmd}\nOutput:\n{output[:2000]}")

            # Feed results back to AI
            result_block = "\n---\n".join(results)
            self.history.append({"role": "assistant", "content": response})
            self.history.append({
                "role": "user",
                "content": f"Command results:\n{result_block}\n\nSummarize findings or give next steps."
            })

        console.print("[dim]Max analysis rounds reached.[/dim]")

    def _extract_tool_commands(self, text: str) -> list:
        """Extract tool commands from AI response (```tool blocks)."""
        cmds = []
        for match in re.finditer(r'```tool\n(.+?)\n```', text, re.DOTALL):
            cmd = match.group(1).strip()
            if cmd:
                cmds.append(cmd)
        if not cmds:
            for match in re.finditer(r'```(?:bash|sh)?\n(.+?)\n```', text, re.DOTALL):
                cmd = match.group(1).strip()
                if cmd and not cmd.startswith("#"):
                    cmds.append(cmd)
        return cmds[:5]

    def _handle_ctf(self, text: str):
        """Handle CTF challenge descriptions."""
        t = text.lower()
        if "pcap" in t:
            console.print("Try: tshark -r *.pcap -Y 'dns' -T fields -e dns.qry.name")
        elif any(x in t for x in ["binary", "elf", "exe"]):
            console.print("Try: file *; strings *; checksec --file=*; gdb -q ./binary")
        elif any(x in t for x in ["stego", "resim", "image"]):
            console.print("Try: binwalk *; strings *; exiftool *; steghide extract -sf *")
        elif any(x in t for x in ["crypto", "sifreli"]):
            console.print("Identify cipher type, try frequency analysis or known-plaintext attack")
        elif "forensic" in t or "dump" in t:
            console.print("Try: volatility -f *.mem imageinfo; strings *; foremost *")
        else:
            console.print("Describe challenge type (binary, pcap, stego, crypto, web) for specific tools.")
        self.history.append({"role": "assistant", "content": f"CTF: {text[:60]}"})

    def _cmd_scan(self, text: str):
        """Run full scan from chat."""
        from .orchestrator import SuvariOrchestrator
        ws = Workspace(text.split()[-1])
        orchestrator = SuvariOrchestrator(
            target_url=text.split()[-1],
            workspace=ws,
            fast="-f" in text or "--fast" in text,
            verbose=False,
        )
        orchestrator.run()
        self.last_scan_dir = ws.path
        self.history.append({
            "role": "assistant",
            "content": f"Scan complete. Report: {ws.path / 'report.md'}"
        })

    def _cmd_recon(self, text: str):
        """Run recon from chat."""
        from .agents.recon import ReconAgent
        url = text.split()[-1]
        if not url.startswith("http"):
            url = "https://" + url
        ws = Workspace(f"recon-{url.split('/')[-1]}")
        agent = ReconAgent("recon", self.llm, ws, self.tools)
        results = agent.run({"target_url": url})
        for k, v in results.items():
            if isinstance(v, str) and not v.startswith("("):
                console.print(f"  {k}: {v[:200]}")
        self.history.append({"role": "assistant", "content": f"Recon complete for {url}"})

    def _show_report(self):
        """Show last scan report."""
        report_file = self.last_scan_dir / "report.md"
        if not report_file.exists():
            console.print("[yellow]No report found in last scan[/yellow]")
            return
        text = report_file.read_text()
        console.print(text[:2000])

    def _list_scans(self):
        """List previous scans."""
        output_dir = Path("output")
        if not output_dir.exists():
            console.print("[yellow]No scans found[/yellow]")
            return
        dirs = sorted(output_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)[:10]
        for d in dirs:
            report = d / "report.md"
            age = f"{report.stat().st_mtime:.0f}" if report.exists() else "no report"
            console.print(f"  {d.name} ({age})")
