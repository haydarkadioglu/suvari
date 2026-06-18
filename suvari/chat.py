"""
Chat — interactive pentesting conversation with P-E-R (Planner-Executor-Reflector).
Loads existing scan findings, saves results to scan directory.
"""

from typing import Optional
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from .llm import LLMClient
from .workspace import Workspace
from .tools.runner import ToolRunner
from .mode import ScanMode
from .config import load_config
import re, shlex, json

console = Console()

SYSTEM_PROMPT = """You are Suvari, an AI-powered pentesting assistant. You have access to security tools.

YOUR JOB:
Run actual security tests. Don't just read files - use tools like curl, nmap, nuclei, whatweb, gobuster, etc.

HOW TO USE TOOLS:
Write commands in code blocks with language "tool":
```tool
curl -sI https://example.com
nmap -F example.com
```

RULES:
- Run 3-5 different tests per round. Check headers, endpoints, technologies.
- If given existing findings, verify each one with actual tool execution.
- Don't stop after 1 test - keep digging until you've checked everything relevant.
- Look for: CORS, missing headers, exposed files, information disclosure, SQLi, XSS.
- Final response: concise summary of findings. List what's vulnerable and what's safe.
- Never say "I'll check" - just run the tools.
- Respond in the same language as the user.
"""


class ChatSession:
    def __init__(self):
        cfg = load_config()
        self.llm = LLMClient(provider=cfg.get("provider", "deepseek"), model=cfg.get("model"))
        self.tools = ToolRunner()
        self.history = []
        self.last_scan_dir: Optional[Path] = None

    def run(self):
        console.print("[bold][SUVARI] — AI Pentester Assistant[/bold]")
        console.print("Type 'help' for commands, 'exit' to quit.\n")
        while True:
            try:
                text = Prompt.ask("You")
            except (EOFError, KeyboardInterrupt):
                console.print("\nGoodbye!")
                break
            t = text.strip().lower()
            if t in ("exit", "quit", "q"):
                console.print("Goodbye!")
                break
            if t == "help":
                self._show_help()
                continue
            self._handle_input(text)

    def _show_help(self):
        t = Table(show_header=False, border_style="dim")
        t.add_row("scan <url>", "Full security scan")
        t.add_row("recon <url>", "Quick reconnaissance")
        t.add_row("report", "Show last scan report")
        t.add_row("history", "List previous scans")
        t.add_row("exit", "Quit chat")
        console.print(t)
        console.print('\n  "check CORS on example.com"')
        console.print('  "find subdomains for example.com"')

    def _handle_input(self, text: str):
        t = text.strip().lower()

        # Detect scan directory path first
        path_match = re.search(r'(/home/[^\s]*output/[^\s]+)', text)
        if path_match:
            self.last_scan_dir = Path(path_match.group(1))

        if t.startswith("scan "):
            self._cmd_scan(text)
            return
        if t.startswith("recon "):
            self._cmd_recon(text)
            return
        if t in ("rapor", "report", "findings", "bulgular"):
            self._show_report()
            return
        if t in ("history", "scans", "list"):
            self._list_scans()
            return
        self._per_loop(text)

    def _per_loop(self, user_input: str, max_rounds: int = 20):
        """P-E-R loop. Loads scan findings if path provided. Saves results to scan dir."""
        self.history.append({"role": "user", "content": user_input})
        avail = ", ".join(sorted(self.tools.available_tools().keys()))
        context = f"Available tools: {avail}"

        # Detect scan directory in input
        path_match = re.search(r'(/home/[^\s]+output/[^\s]+)', user_input)
        scan_dir = Path(path_match.group(1)) if path_match else self.last_scan_dir

        # Load existing findings for deeper analysis
        existing_findings = []
        if scan_dir:
            fpath = scan_dir / "analysis" / "findings.json"
            if fpath.exists():
                try:
                    data = json.loads(fpath.read_text())
                    vulns = data.get("vulnerabilities", [])
                    for v in vulns[:15]:
                        existing_findings.append(f"[{v.get('severity','?')}] {v.get('type','?')} @ {v.get('location','?')}")
                    if existing_findings:
                        context += "\n\nExisting findings (dive deeper on each):\n" + "\n".join(existing_findings)
                except Exception:
                    pass

        report_lines = [f"# Chat: {datetime.now().isoformat()[:19]}", f"## Query: {user_input}", ""]
        if existing_findings:
            report_lines.append("### Existing Findings")
            report_lines.extend(existing_findings)

        for turn in range(max_rounds):
            messages = [{"role": "system", "content": SYSTEM_PROMPT + "\n\n" + context}]
            messages += self.history[-10:]

            with console.status("Thinking...", spinner="dots"):
                response = self.llm.chat(messages=messages, temperature=0.3, max_tokens=1024, stream=False)

            commands = self._extract_tool_commands(response)

            if not commands:
                console.print(response)
                self.history.append({"role": "assistant", "content": response})
                report_lines.append(f"## Result\n{response}\n")
                break

            results = []
            for cmd in commands:
                with console.status(f" Running: {cmd[:50]}...", spinner="dots"):
                    try:
                        if "|" in cmd:
                            import subprocess as sp
                            r = sp.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                            output = r.stdout + r.stderr
                        else:
                            output = self.tools.run(shlex.split(cmd), timeout=60)
                    except Exception as e:
                        output = f"(error: {e})"

                console.print(f"  $ {cmd}")
                preview = output[:500].replace("\n", "\n  ")
                if preview:
                    console.print(f"  {preview}")
                results.append(f"Command: {cmd}\nOutput:\n{output[:2000]}")

            report_lines.append(f"### Round {turn+1}")
            for r in results:
                report_lines.append(f"```\n{r[:500]}\n```")

            result_block = "\n---\n".join(results)
            self.history.append({"role": "assistant", "content": response})
            # Push for more testing unless there's been substantial analysis
            more_msg = f"Results:\n{result_block}\n\nKeep testing. Check more endpoints, different methods, deeper analysis. Run at least 3-5 more commands."
            if turn >= max_rounds - 2:
                more_msg = f"Results:\n{result_block}\n\nFinal round. Give comprehensive summary of all findings."
            self.history.append({"role": "user", "content": more_msg})

        # Save to scan dir (preferred) or chat dir
        try:
            save_dir = scan_dir if scan_dir else Path("output") / "chat"
            save_dir.mkdir(parents=True, exist_ok=True)
            f = save_dir / f"chat_{datetime.now().strftime('%H%M%S')}.md"
            f.write_text("\n".join(report_lines))
            console.print(f"[dim]Saved: {f}[/dim]")
            self.last_scan_dir = save_dir
        except Exception:
            pass

    def _extract_tool_commands(self, text: str) -> list:
        cmds = []
        for m in re.finditer(r'```tool\n(.+?)\n```', text, re.DOTALL):
            c = m.group(1).strip()
            if c:
                cmds.append(c)
        if not cmds:
            for m in re.finditer(r'```(?:bash|sh)?\n(.+?)\n```', text, re.DOTALL):
                c = m.group(1).strip()
                if c and not c.startswith("#"):
                    cmds.append(c)
        return cmds[:5]

    def _cmd_scan(self, text: str):
        from .orchestrator import SuvariOrchestrator
        url = text.split()[-1]
        ws = Workspace(url)
        SuvariOrchestrator(target_url=url, workspace=ws).run()
        self.last_scan_dir = ws.path

    def _cmd_recon(self, text: str):
        from .agents.recon import ReconAgent
        url = text.split()[-1]
        if not url.startswith("http"):
            url = "https://" + url
        ws = Workspace("recon")
        ReconAgent("recon", self.llm, ws, self.tools).run({"target_url": url})

    def _show_report(self):
        if not self.last_scan_dir:
            console.print("[yellow]No scan results yet.[/yellow]")
            return
        r = self.last_scan_dir / "report.md"
        if r.exists():
            console.print(r.read_text()[:2000])
        else:
            console.print("[yellow]No report file found.[/yellow]")

    def _list_scans(self):
        d = Path("output")
        if not d.exists():
            return
        for p in sorted(d.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True)[:10]:
            console.print(f"  {p.name}")
