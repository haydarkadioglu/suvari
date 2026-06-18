"""
Chat — interactive pentesting conversation.
Like talking to a security expert. Give commands naturally.
"""

import subprocess
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

SYSTEM_PROMPT = """You are Suvari, an AI-powered pentesting assistant. Be concise - respond in 2-3 sentences max unless asked for details.

For CTF: describe what to do, suggest specific commands.
For scan results: list findings briefly, no narrative.
For report queries: read the actual files, don't describe what you would do.
For general questions: direct answer, no fluff. Never say "I'll check" - actually do it.

Respond in the same language as the user."""


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
        if any(kw in t for kw in ["rapor", "report", "show results", "findings", "bulgular"]):
            if self.last_scan_dir:
                self._show_report()
                return
        if t.startswith("cors ") or "cors" in t[:20]:
            self._cmd_cors(text)
            return
        if t.startswith("check ") or "kontrol et" in t or "test et" in t or "dene" in t:
            self._cmd_check(text)
            return

        # CTF detection - strict: must mention a CTF type + file/description
        ctf_keywords = ["ctf", "pcap dosyası", "binary var", "buffer overflow",
                        "stego", "forensic", "crypto challenge", "reverse engineering",
                        "flag arıyorum", "challenge var", "rootme", "hackthebox",
                        "tryhackme", "htb", "exploit yaz"]
        ctf_count = sum(1 for kw in ctf_keywords if kw in t)
        has_file_type = any(kw in t for kw in ["pcap", "binary", "resim", "image", "exe", "elf",
                                                  "dump", "sifreli", "encrypted", "encoded"])
        if ctf_count >= 2 or (ctf_count >= 1 and has_file_type):
            self._handle_ctf(text)
            return

        # Subdomain enumeration detection
        subdomain_keywords = ["subdomain", "alt domain", "alt alan", "dns", "alt-domain",
                               "find subdomain", "enum subdomain", "subdomain discover",
                               "subdomain enum"]
        if any(kw in t for kw in subdomain_keywords):
            self._cmd_bugbounty(text)
            return

        # Exploit/attack keywords
        if any(kw in t for kw in ["exploit", "attack", "verify", "try to hack", "poc"]):
            if self.last_scan_dir:
                self._cmd_attack(text)
                return
            return

        # General chat — let LLM respond with streaming
        console.print()
        try:
            response = self.llm.chat(
                messages=self.history[-6:],
                temperature=0.3,
                max_tokens=1024,
                stream=True,
            )
            self.history.append({"role": "assistant", "content": response})
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

    def _handle_ctf(self, text: str):
        """Handle CTF challenge descriptions - suggest tools and commands."""
        from .config import load_config

        t = text.lower()
        if "pcap" in t or "dns" in t:
            console.print("Try: tshark -r *.pcap -Y 'dns' -T fields -e dns.qry.name")
        elif any(x in t for x in ["binary", "elf", "exe", "buffer overflow"]):
            console.print("Try: file *; checksec *; strings *; gdb -q ./binary")
        elif any(x in t for x in ["stego", "resim", "image", "jpg", "png"]):
            console.print("Try: binwalk *; strings *; exiftool *; steghide extract -sf *")
        elif any(x in t for x in ["crypto", "sifreli", "encrypted"]):
            console.print("Identify cipher type, try frequency analysis or brute force")
        elif "forensic" in t or "dump" in t:
            console.print("Try: volatility -f *.mem imageinfo; strings *; foremost *")
        else:
            console.print("Describe the challenge type (binary, pcap, stego, crypto, web) for specific tools.")
        self.history.append({"role": "assistant", "content": f"CTF: {text[:60]}"})
    def _quick_file_type(self, fpath: Path) -> str:
        """Quick file type detection."""
        try:
            result = subprocess.run(["file", "-b", str(fpath)], capture_output=True, text=True, timeout=5)
            return result.stdout.strip()[:60] if result.stdout else "unknown"
        except Exception:
            return "unknown"

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
        """Flexible endpoint check - handles various security tests."""
        from urllib.parse import urlparse

        # Extract URL from text
        import re
        url_match = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)', text)
        base_url = url_match.group(0) if url_match else self._get_last_target()
        if not base_url:
            console.print("[yellow]Specify a URL. Example: check /api on site.com[/yellow]")
            return
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"
        t = text.lower()

        # Determine check type from keywords
        if "cors" in t:
            # CORS test
            out = self.tools.run(
                ["curl", "-sI", "-H", "Origin: https://evil.com", base_url, "--max-time", "5"], timeout=10
            )
            if "Access-Control-Allow-Origin" in out:
                console.print(f"[red]CORS misconfiguration![/red] Origin reflected in response.")
            else:
                console.print("No CORS misconfiguration detected.")
            for line in out.splitlines()[:10]:
                if "access-control" in line.lower():
                    console.print(f"  {line}")

        elif "header" in t or "security" in t or "güvenlik" in t:
            # Header check
            out = self.tools.run(["curl", "-sI", "-L", base_url, "--max-time", "5"], timeout=10)
            checks = {"X-Frame-Options": "Clickjacking", "X-Content-Type-Options": "MIME sniff",
                       "Content-Security-Policy": "CSP", "Strict-Transport-Security": "HSTS"}
            for hdr, name in checks.items():
                if hdr not in out:
                    console.print(f"  Missing: {hdr} ({name})")
            for line in out.splitlines()[:15]:
                console.print(f"  {line}")

        elif "sql" in t or "sqli" in t:
            # Quick SQLi test
            test_url = f"{base_url}?id=1'"
            out = self.tools.run(["curl", "-s", test_url, "--max-time", "5"], timeout=10)
            if "sql" in out.lower() or "you have an error" in out.lower():
                console.print("[red]Possible SQL injection detected![/red]")
                console.print(f"  Try: sqlmap -u '{base_url}?id=1' --batch")
            else:
                console.print("No obvious SQL error detected.")

        elif "xss" in t:
            # Quick XSS test
            test_url = f"{base_url}?q=<script>alert(1)</script>"
            out = self.tools.run(["curl", "-s", test_url, "--max-time", "5"], timeout=10)
            if "<script>alert(1)</script>" in out:
                console.print("[red]Reflected XSS detected![/red]")
            else:
                console.print("No obvious XSS detected.")

        else:
            # Generic: just show response
            out = self.tools.run(["curl", "-sI", base_url, "--max-time", "5"], timeout=10)
            lines = out[:500].split("\n")
            for line in lines[:10]:
                console.print(f"  {line}")

    def _cmd_cors(self, text: str):
        """CORS misconfiguration test."""
        import re
        url_match = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)', text)
        target = url_match.group(0) if url_match else self._get_last_target()
        if not target:
            console.print("[yellow]Specify URL[/yellow]")
            return
        if not target.startswith("http"):
            target = f"https://{target}"

        console.print(f"Testing CORS on {target}...")
        for origin in ["https://evil.com", "null", "https://example.com"]:
            out = self.tools.run(
                ["curl", "-sI", "-H", f"Origin: {origin}", target, "--max-time", "5"], timeout=10
            )
            reflected = "Access-Control-Allow-Origin" in out
            status = "[red]VULNERABLE[/red]" if reflected else "[green]OK[/green]"
            console.print(f"  Origin: {origin[:25]:25s} {status}")

    def _get_last_target(self) -> str:
        """Get the last scanned URL from history."""
        for msg in reversed(self.history):
            if msg["role"] == "assistant" and "Scan complete" in msg.get("content", ""):
                for word in msg["content"].split():
                    if word.startswith("http"):
                        return word.rstrip(".")
        return ""

    def _cmd_bugbounty(self, text: str):
        """Run subdomain enumeration from chat."""
        import re
        from .agents.bugbounty import BugBountyAgent
        from .workspace import Workspace

        domain_match = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text)
        if not domain_match:
            console.print("[yellow]Which domain?[/yellow]")
            return
        domain = domain_match.group(1).split("/")[0]
        cfg = load_config()
        llm = LLMClient(provider=cfg.get("provider", "deepseek"), model=cfg.get("model"))
        ws = Workspace(f"bb-{domain}")
        tr = ToolRunner()
        agent = BugBountyAgent("bugbounty", llm, ws, tr)
        console.print(f"  Enumerating {domain}...")
        results = agent.run({"target_url": f"https://{domain}"})
        subs = results.get("subdomains", [])
        urls = results.get("urls", [])
        if subs:
            console.print(f"\n  Subdomains ({len(subs)}):")
            for s in subs[:20]:
                console.print(f"    {s}")
        else:
            console.print("  No subdomains found")
        console.print(f"  URLs discovered: {len(urls)}")
        self.history.append({"role": "assistant", "content": f"Subdomain enumeration: {len(subs)} found for {domain}"})

    def _cmd_attack(self, text: str):
        """Run attack on last scan results from chat."""
        from .orchestrator import SuvariOrchestrator
        from .workspace import Workspace
        from .tools.runner import ToolRunner
        from .llm import LLMClient
        from .agents.exploiter import ExploiterAgent

        scan_dir = self.last_scan_dir
        findings_file = scan_dir / "analysis" / "findings.json"
        if not findings_file.exists():
            console.print("[yellow]No findings.json in that scan[/yellow]")
            return

        import json
        findings = json.loads(findings_file.read_text())
        vulns = findings.get("vulnerabilities", [])
        if not vulns:
            console.print("[yellow]No vulnerabilities found in scan[/yellow]")
            return

        console.print(f"  Exploiting {len(vulns)} findings...")
        cfg = load_config()
        llm = LLMClient(provider=cfg.get("provider", "deepseek"), model=cfg.get("model"))
        ws = Workspace(f"attack-{scan_dir.name}")
        tr = ToolRunner()
        agent = ExploiterAgent("exploiter", llm, ws, tr)
        context = {
            "target_url": vulns[0].get("location", ""),
            "analysis": findings,
            "fast": False,
        }
        results = agent.run(context)
        successes = sum(1 for r in results.get("exploits", []) if r.get("success"))
        console.print(f"[green]Done: {successes} confirmed[/green] [dim]{ws.path}[/dim]")
        self.history.append({"role": "assistant", "content": f"Exploitation complete: {successes} confirmed"})

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
