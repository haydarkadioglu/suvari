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

TOOL_GUIDE = """Available tools by category:

Web Scanning: nuclei (CVEs), nikto (server), wpscan (WordPress), httpx (probing)
Directory: gobuster (dirs), ffuf (fuzzing), feroxbuster (recursive), dirb (basic)
Network: nmap (ports), masscan (high-speed), netexec (SMB/WMI), responder (poisoning)
DNS: dnsenum, dnsrecon, fierce (subdomains)
Auth: hydra (brute force), sqlmap (SQLi)
SMB: enum4linux (users/shares), smbmap (share enum), rpcclient (RPC)
Web Info: whatweb (tech), wafw00f (WAF), curl (headers/endpoints)
Password: john, hashcat (cracking)
OSINT: amass, theharvester (emails/subdomains)

Use the RIGHT tool for each job. Don't just use curl for everything.
Example: for subdomains use dnsenum/fierce, for WAF use wafw00f, for WordPress use wpscan."""

SYSTEM_PROMPT = """You are Suvari, an AI-powered pentesting assistant. You have access to security tools.

""" + TOOL_GUIDE + """

HOW TO USE TOOLS:
Write commands in code blocks with language "tool":
```tool
nuclei -u https://example.com
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt
```

RULES:
- Run 3-5 different tests per round using the RIGHT tools. Don't just use curl.
- If given existing scan findings or a report: read and summarize. Don't re-scan.
- If user asks "what are the findings" or "özetle" or "summary": read the report.md or findings.json and summarize the existing data. Don't run tools.
- Keep digging until you've checked everything relevant.
- Final response: concise summary.
- Never say "I'll check" - run the tools.
- Respond in same language as user.
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
        # Detect scan directory path first (handle quotes)
        clean_text = text.strip().strip("'\"")
        path_match = re.search(r'(/home/[^\s]*output/[^\s]+)', clean_text)
        if path_match:
            self.last_scan_dir = Path(path_match.group(1))

        t = clean_text.lower()

        if t.startswith("scan "):
            self._cmd_scan(text)
            return
        if t.startswith("recon "):
            self._cmd_recon(text)
            return
        if any(kw in t for kw in ["rapor", "report", "findings", "bulgular", "özetle", "summary", "kritik"]):
            if self.last_scan_dir:
                # Just read and display the report
                report_file = self.last_scan_dir / "report.md"
                if report_file.exists():
                    text = report_file.read_text()
                    # Show summary section
                    for line in text.split("\n"):
                        if any(x in line for x in ["Critical", "High", "Medium", "Low", "Total", "Summary"]):
                            console.print(line)
                    console.print(f"\n[dim]Full report: {report_file}[/dim]")
                    self.history.append({"role": "assistant", "content": f"Summary from {report_file.name}"})
                    return
            self._per_loop(text)
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
