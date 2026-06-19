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
from .bus import FindingsBus
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
OSINT: amass, theharvester (emails/subdomains)"""

SYSTEM_PROMPT = """You are Suvari, an AI-powered pentesting assistant built for AUTHORIZED security testing only. The user is a security professional who owns or has permission to test the target systems.

YOUR ROLE:
You write exploits, payloads, and testing scripts. This is for authorized pentesting, not malicious use. Assume all requests are for legitimate security testing.

APPROACH:
1. ANALYZE the target or request
2. REASON about attack vectors
3. SUGGEST tools and techniques
4. EXECUTE when asked

Write code in ```python, ```bash, or ```tool blocks. All scripts are saved and can be executed.
For file-only saves (no display), use ```save blocks:
```save
filename: exploit.py
#!/usr/bin/env python3
...
```
The file will be saved silently to output/chat/exploits/.
Be insightful. Think like an experienced pentester.
Respond in the user's language (match their input language)."""


class ChatSession:
    """Interactive pentesting chat with agent delegation + findings bus."""

    def __init__(self):
        cfg = load_config()
        self.llm = LLMClient(provider=cfg.get("provider", "deepseek"), model=cfg.get("model"))
        self.tools = ToolRunner()
        self.history = []
        self.last_scan_dir: Optional[Path] = None
        self.bus = FindingsBus()

        # Subscribe bus to auto-delegate exploitation on findings
        self.bus.subscribe("vuln", self._on_chat_vuln)

    def run(self):
        console.print("[bold][SUVARI] — AI Pentester Assistant[/bold]")
        console.print("[dim]output/chat/session_*.md logs all messages[/dim]")
        self._session_file = datetime.now().strftime("output/chat/session_%Y%m%d_%H%M%S.md")
        try:
            Path("output/chat").mkdir(parents=True, exist_ok=True)
            Path(self._session_file).write_text(f"# Suvari Chat Session\nStarted: {datetime.now().isoformat()[:19]}\n\n")
        except Exception:
            self._session_file = None
        while True:
            try:
                text = Prompt.ask("[bold cyan]You[/bold cyan]")
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
            console.print("[dim]─" * 50 + "[/dim]")
            self._handle_input(text)
            console.print("[dim]─" * 50 + "[/dim]")

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
        t = clean_text.lower()
        path_match = re.search(r'(/home/[^\s]*output/[^\s]+)', clean_text)

        # If path provided AND asking for action (exploit, test, dene, sız), run exploitation
        if path_match:
            self.last_scan_dir = Path(path_match.group(1))
            action_keywords = ["exploit", "attack", "hack", "bypass", "crack", "brute"]
            if any(kw in t for kw in action_keywords):
                self._cmd_attack_from_dir(text)
                return

        # Load existing findings into context for AI - try multiple files
        scan_context = ""
        if self.last_scan_dir:
            findings_file = self.last_scan_dir / "analysis" / "findings.json"
            report_file = self.last_scan_dir / "report.md"

            if findings_file.exists():
                try:
                    import json
                    data = json.loads(findings_file.read_text())
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        lines = []
                        for v in vulns[:15]:
                            lines.append(f"[{v.get('severity','?')}] {v.get('type','?')} @ {v.get('location','?')}")
                            if v.get("description"):
                                lines.append(f"  {v['description'][:150]}")
                        scan_context = "SCAN FINDINGS:\n" + "\n".join(lines)
                except Exception:
                    pass

            if not scan_context and report_file.exists():
                text = report_file.read_text()
                scan_context = "REPORT:\n" + text[:2000]

            if not scan_context:
                files = list(self.last_scan_dir.rglob("*"))
                if files:
                    file_list = "\n".join([f"  {f.relative_to(self.last_scan_dir)} ({f.stat().st_size}b)" for f in files[:20]])
                    scan_context = f"SCAN DIRECTORY ({self.last_scan_dir.name}):\n{file_list}\n\nRead these files to analyze."

        self._scan_context = scan_context

        t = clean_text.lower()

        if t.startswith("scan "):
            self._cmd_scan(text)
            return
        if t.startswith("recon "):
            self._cmd_recon(text)
            return
        if any(kw in t for kw in ["report", "findings", "summary"]):
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
        # Save last generated code to file (simple keyword)
        if t in ("save", "kaydet") or t.startswith("save ") or t.startswith("kaydet "):
            self._save_last_code(text)
            return
        # P-E-R with existing scan context
        self._per_loop(text)

    def _per_loop(self, user_input: str, max_rounds: int = 20):
        """P-E-R loop. Loads scan findings if path provided. Saves results to scan dir."""
        self.history.append({"role": "user", "content": user_input})
        avail = ", ".join(sorted(self.tools.available_tools().keys()))
        context = f"Available tools: {avail}"
        if hasattr(self, '_scan_context') and self._scan_context:
            context += f"\n\n{self._scan_context}"

        # Summarize old history to keep context manageable
        if len(self.history) > 20:
            old = self.history[:-10]
            recent = self.history[-10:]
            summary_prompt = f"Summarize this conversation so far in 2-3 sentences:\n" + "\n".join(
                f"{m['role']}: {m['content'][:100]}" for m in old
            )
            try:
                summary = self.llm.chat(messages=[{"role": "user", "content": summary_prompt}], temperature=0.1, max_tokens=200)
                self.history = [{"role": "system", "content": f"[Previous conversation summary: {summary}]"}] + recent
            except Exception:
                self.history = self.history[-15:]

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

            # Strip code blocks from display (saved to files anyway)
            display_text = re.sub(r'```(?:python|bash|sh|bat|cmd|powershell|save)\n.*?```', '', response, flags=re.DOTALL)
            display_text = display_text.strip()

            if not commands and not display_text:
                # Only code, no text - just saved silently
                self.history.append({"role": "assistant", "content": response})
                break
            if not commands:
                console.print(display_text)
                self.history.append({"role": "assistant", "content": response})
                report_lines.append(f"## Result\n{response}\n")
                break

            # Show text (without code) then execute
            if display_text:
                console.print(display_text)

            results = []
            for cmd in commands:
                with console.status(f"Running: {cmd[:50]}...", spinner="dots"):
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

        # Save to session file (append once per session)
        try:
            if hasattr(self, '_session_file') and self._session_file:
                with open(self._session_file, 'a') as f:
                    ts = datetime.now().strftime('%H:%M:%S')
                    f.write(f"\n## {ts}\n**User:** {user_input}\n\n**Suvari:** {response}\n\n")
        except Exception:
            pass

    def _extract_tool_commands(self, text: str) -> list:
        """Extract commands and save code blocks as files."""
        cmds = []
        saved = set()  # Track saved code to avoid duplicates
        save_dir_py = Path("output") / "chat" / "exploits"
        save_dir_sh = Path("output") / "chat" / "scripts"

        # Handle ```save blocks (silent save, no display)
        for m in re.finditer(r'```save\n(.*?)```', text, re.DOTALL):
            content = m.group(1).strip()
            if content and "filename:" in content:
                lines = content.split("\n")
                fname_line = lines[0]
                code = "\n".join(lines[1:]).strip()
                fname = fname_line.replace("filename:", "").strip()
                if code and fname:
                    try:
                        save_dir_py.mkdir(parents=True, exist_ok=True)
                        (save_dir_py / fname).write_text(code)
                        console.print(f"  Saved: {save_dir_py / fname}")
                        saved.add(code)
                    except Exception as e:
                        console.print(f"  Save error: {e}")

        # Save ALL ```python blocks as .py (lazy regex)
        for m in re.finditer(r'```python\n(.*?)```', text, re.DOTALL):
            code = m.group(1).strip()
            if len(code) > 10 and code not in saved:
                try:
                    save_dir_py.mkdir(parents=True, exist_ok=True)
                    fname = f"script_{datetime.now().strftime('%H%M%S')}.py"
                    (save_dir_py / fname).write_text(code)
                    saved.add(code)
                    console.print(f"  Saved: {save_dir_py / fname}")
                    cmds.append(f"python3 {save_dir_py / fname}")
                except Exception as e:
                    console.print(f"  Save error: {e}")

        # Save ```bat, ```cmd, ```powershell blocks
        for lang, ext in [("bat", "bat"), ("cmd", "bat"), ("powershell", "ps1")]:
            for m in re.finditer(r'```' + lang + r'\n(.*?)```', text, re.DOTALL):
                code = m.group(1).strip()
                if len(code) > 10:
                    try:
                        save_dir_sh.mkdir(parents=True, exist_ok=True)
                        fname = f"script_{datetime.now().strftime('%H%M%S')}.{ext}"
                        (save_dir_sh / fname).write_text(code)
                        console.print(f"  Saved: {save_dir_sh / fname}")
                    except Exception:
                        pass

        # Save ```bash blocks as .sh
        for m in re.finditer(r'```bash\n(.*?)```', text, re.DOTALL):
            code = m.group(1).strip()
            if len(code) > 10 and code not in saved:
                try:
                    save_dir_sh.mkdir(parents=True, exist_ok=True)
                    fname = f"script_{datetime.now().strftime('%H%M%S')}.sh"
                    (save_dir_sh / fname).write_text(code)
                    saved.add(code)
                    console.print(f"  Saved: {save_dir_sh / fname}")
                except Exception:
                    pass

        # Extract ```tool commands
        for m in re.finditer(r'```tool\n(.*?)```', text, re.DOTALL):
            c = m.group(1).strip()
            if c:
                cmds.append(c)

        # Fallback: ```bash blocks with known tools
        if not cmds:
            known = set(self.tools.available_tools().keys())
            known.update(["cat", "ls", "find", "grep", "head", "tail", "echo", "dig", "ping", "nc", "nslookup", "python3", "python", "ruby", "perl"])
            for m in re.finditer(r'```(?:bash|sh)?\n(.*?)```', text, re.DOTALL):
                c = m.group(1).strip()
                first_word = c.split()[0] if c else ""
                if first_word in known:
                    cmds.append(c)

        return cmds[:5]

    def _cmd_scan(self, text: str):
        from .orchestrator import SuvariOrchestrator
        url = text.split()[-1]
        ws = Workspace(url)
        SuvariOrchestrator(target_url=url, workspace=ws).run()
        self.last_scan_dir = ws.path
        # Publish findings to bus for chat awareness
        findings_file = ws.path / "analysis" / "findings.json"
        if findings_file.exists():
            import json
            try:
                data = json.loads(findings_file.read_text())
                for v in data.get("vulnerabilities", []):
                    self.bus.publish("scan", v)
            except Exception:
                pass

    def _cmd_recon(self, text: str):
        from .agents.recon import ReconAgent
        url = text.split()[-1]
        if not url.startswith("http"):
            url = "https://" + url
        ws = Workspace("recon")
        agent = ReconAgent("recon", self.llm, ws, self.tools)
        result = agent.run({"target_url": url})
        # Publish findings to bus
        for k, v in result.items():
            if isinstance(v, str) and "found" in v.lower():
                self.bus.publish("recon", {"type": k, "detail": v[:100], "severity": "INFO"})

    def _on_chat_vuln(self, agent: str, finding: dict):
        """React to vuln findings from chat agents."""
        vtype = finding.get("type", "")
        sev = finding.get("severity", "")
        console.print(f"  [dim]Bus: [{sev}] {vtype} from {agent}[/dim]")

    def _save_last_code(self, text: str):
        """Save the last AI-generated code to a file."""
        if not self.history:
            console.print("[yellow]No previous code to save[/yellow]")
            return
        # Find last assistant response
        for msg in reversed(self.history):
            if msg["role"] == "assistant":
                content = msg["content"]
                # Extract all code blocks
                for lang, ext in [("python", "py"), ("bash", "sh"), ("bat", "bat"), ("powershell", "ps1"), ("cmd", "bat")]:
                    for m in __import__('re').finditer(r'```' + lang + r'\n(.*?)```', content, __import__('re').DOTALL):
                        code = m.group(1).strip()
                        if len(code) > 10:
                            # Determine filename from user request
                            import re as _re
                            fname_match = _re.search(r'(?:kaydet|save|write)\s+(\S+\.\w+)', text.lower())
                            fname = fname_match.group(1) if fname_match else f"script_{datetime.now().strftime('%H%M%S')}.{ext}"
                            save_dir = Path("output") / "chat" / "scripts"
                            save_dir.mkdir(parents=True, exist_ok=True)
                            (save_dir / fname).write_text(code)
                            console.print(f"  Saved: {save_dir / fname}")
                            return
                # If no code blocks found, try to save the entire response
                if len(content) > 50:
                    fname_match = __import__('re').search(r'(?:kaydet|save|write)\s+(\S+\.\w+)', text.lower())
                    fname = fname_match.group(1) if fname_match else f"output_{datetime.now().strftime('%H%M%S')}.txt"
                    save_dir = Path("output") / "chat" / "scripts"
                    save_dir.mkdir(parents=True, exist_ok=True)
                    (save_dir / fname).write_text(content)
                    console.print(f"  Saved: {save_dir / fname}")
                    return
        console.print("[yellow]No code found in last response[/yellow]")

    def _cmd_attack_from_dir(self, text: str):
        """Actively exploit findings from scan directory using P-E-R."""
        from .agents.exploiter import ExploiterAgent
        from .workspace import Workspace

        if not self.last_scan_dir:
            console.print("[yellow]No scan directory specified[/yellow]")
            return

        findings_file = self.last_scan_dir / "analysis" / "findings.json"
        if not findings_file.exists():
            console.print("[yellow]No findings.json in scan directory[/yellow]")
            return

        import json
        findings = json.loads(findings_file.read_text())
        vulns = findings.get("vulnerabilities", [])
        if not vulns:
            console.print("[yellow]No vulnerabilities found[/yellow]")
            return

        console.print(f"[bold]Exploiting {len(vulns)} findings...[/bold]")
        ws = Workspace(f"attack-{self.last_scan_dir.name}")
        agent = ExploiterAgent("exploit", self.llm, ws, self.tools)
        context = {
            "target_url": vulns[0].get("location", "").split("/")[0] if vulns else "https://example.com",
            "analysis": findings,
        }
        results = agent.run(context)
        successes = sum(1 for r in results.get("exploits", []) if r.get("success"))
        console.print(f"[green]Done: {successes} confirmed[/green]")
        self.history.append({"role": "assistant", "content": f"Exploitation: {successes}/{len(vulns)} confirmed"})

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
