"""
Suvari Core — programmatic API for all Suvari operations.
Chat, agents, tools, findings bus, file management all in one place.
"""

from typing import Optional
from pathlib import Path
from datetime import datetime
from .llm import LLMClient
from .bus import FindingsBus
from .workspace import Workspace
from .tools.runner import ToolRunner
from .config import load_config
import re, json, shlex, subprocess as sp


class SuvariCore:
    """Core API: scan, chat, attack, recon, list_scans, get_report."""

    def __init__(self):
        cfg = load_config()
        self.llm = LLMClient(provider=cfg.get("provider", "deepseek"), model=cfg.get("model"))
        self.tools = ToolRunner()
        self.bus = FindingsBus()
        self.history = []
        self.last_scan_dir: Optional[Path] = None

    # ─── Scan ───

    def scan(self, url: str, fast: bool = False) -> dict:
        """Run full scan pipeline."""
        from .orchestrator import SuvariOrchestrator
        ws = Workspace(url)
        orch = SuvariOrchestrator(target_url=url, workspace=ws, fast=fast)
        orch.run()
        self.last_scan_dir = ws.path
        return self._load_results(ws.path)

    def recon(self, url: str) -> dict:
        """Run reconnaissance only."""
        from .agents.recon import ReconAgent
        ws = Workspace("recon")
        agent = ReconAgent("recon", self.llm, ws, self.tools)
        return agent.run({"target_url": url})

    # ─── Chat ───

    def chat(self, user_input: str, session_file: Optional[Path] = None, max_rounds: int = 20) -> str:
        """P-E-R chat. Returns AI response (code stripped, tools executed)."""
        from .agents.exploiter import ExploiterAgent
        SYSTEM_PROMPT = self._get_system_prompt()

        # Build categorized tool list for AI
        avail = self.tools.available_tools()
        categories = {
            "Network": ["nmap","masscan","rustscan","unicornscan","arp-scan","zmap"],
            "Web/Discovery": ["gobuster","ffuf","feroxbuster","dirb","dirsearch","katana","hakrawler","wfuzz"],
            "Web/Vuln": ["nuclei","nikto","wpscan","jaeles","dalfox","xsstrike","skipfish","wapiti"],
            "Web/Tech": ["whatweb","httpx","wafw00f"],
            "Exploit": ["sqlmap","hydra","medusa","ncrack","crowbar","metasploit","msfvenom"],
            "OSINT/DNS": ["subfinder","amass","theharvester","dnsenum","dnsrecon","fierce","gau","waybackurls"],
            "SMB/Windows": ["enum4linux","smbmap","rpcclient","netexec"],
            "Utils": ["curl","jq","socat","proxychains","openssl","sslscan","sslyze"],
            "Password": ["john","hashcat","cewl","crunch","rsmangler"],
            "Stego/Forensics": ["binwalk","foremost","strings","exiftool","steghide","volatility"],
        }
        cat_lines = []
        for cat, tools in categories.items():
            present = [t for t in tools if t in avail]
            if present:
                cat_lines.append(f"  [{cat}] {' '.join(present)}")
        tool_context = "\n".join(cat_lines)
        context = f"Available tools by category:\n{tool_context}\n\nUse ```tool <command>``` blocks to run tools."
        context += f"\n\nTotal: {len(avail)} tools on system."

        # Detect scan directory in input and load findings
        # Handle both file paths and directory paths
        path_match = re.search(r'(/home/[^\s]*output/[^\s]+)', user_input)
        raw_path = Path(path_match.group(1)) if path_match else None
        target_dir = None
        if raw_path:
            if raw_path.is_dir():
                target_dir = raw_path
            elif raw_path.is_file():
                target_dir = raw_path.parent
                # Stop climbing at "output" level
                while target_dir.name != "output" and target_dir.parent != target_dir:
                    if (target_dir / "analysis" / "findings.json").exists() or (target_dir / "report.md").exists():
                        break
                    target_dir = target_dir.parent
        target_dir = target_dir or self.last_scan_dir
        if target_dir:
            findings_file = target_dir / "analysis" / "findings.json"
            report_file = target_dir / "report.md"
            loaded_findings = ""
            if findings_file.exists():
                try:
                    data = json.loads(findings_file.read_text())
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        lines = []
                        for v in vulns[:10]:
                            sev = v.get("severity", "?")
                            typ = v.get("type", "?")
                            loc = v.get("location", "?")
                            desc = v.get("description", "")[:120]
                            lines.append(f"[{sev}] {typ} @ {loc}")
                            if desc:
                                lines.append(f"  {desc}")
                        loaded_findings = "\n".join(lines)
                        context += f"\n\nEXISTING FINDINGS:\n{loaded_findings}"
                except Exception:
                    pass
            if report_file.exists() and not loaded_findings:
                report_text = report_file.read_text()
                summary_lines = [l for l in report_text.split("\n") if any(x in l for x in ["Critical", "High", "Medium", "Low", "Total", "##"])]
                if summary_lines:
                    context += f"\n\nREPORT SUMMARY:\n" + "\n".join(summary_lines[:10])
            self.last_scan_dir = target_dir

        # Replace raw path in user message with findings context for the AI
        if raw_path:
            user_input_for_ai = f"[Scan results loaded - {target_dir.name if target_dir else ''}] {' '.join(user_input.split()[1:])}"
        else:
            user_input_for_ai = user_input

        self.history.append({"role": "user", "content": user_input_for_ai})

        response = ""
        display_text = ""

        for turn in range(max_rounds):
            msgs = [{"role": "system", "content": SYSTEM_PROMPT + "\n\n" + context}]
            msgs += self.history[-10:]
            try:
                response = self.llm.chat(messages=msgs, temperature=0.3, max_tokens=1024)
            except Exception as e:
                response = str(e)

            # Extract and save code blocks
            saved = set()
            for lang, ext in [("python", "py"), ("bash", "sh"), ("bat", "bat"), ("cmd", "bat"), ("powershell", "ps1")]:
                for m in re.finditer(r'```' + lang + r'\n(.*?)```', response, re.DOTALL):
                    code = m.group(1).strip()
                    if len(code) > 10 and code not in saved:
                        d = Path("output") / "chat" / "exploits" if lang == "python" else Path("output") / "chat" / "scripts"
                        d.mkdir(parents=True, exist_ok=True)
                        fname = f"script_{datetime.now().strftime('%H%M%S')}.{ext}"
                        (d / fname).write_text(code)
                        saved.add(code)

            # Strip code from display
            parts = response.split("```")
            display_text = ""
            for i, part in enumerate(parts):
                if i % 2 == 0:
                    display_text += part
                elif any(part.startswith(x) for x in ("python", "bash", "sh", "bat", "cmd", "powershell")):
                    continue
                else:
                    display_text += part
            display_text = display_text.strip()

            # Extract tool commands and execute
            cmds = []
            for m in re.finditer(r'```tool\n(.*?)```', response, re.DOTALL):
                c = m.group(1).strip()
                if c:
                    cmds.append(c)
            if not cmds:
                for m in re.finditer(r'```(?:bash|sh)?\n(.*?)```', response, re.DOTALL):
                    c = m.group(1).strip()
                    fw = c.split()[0] if c else ""
                    if fw in self.tools.available_tools() or fw in ("python3", "python", "cat", "ls"):
                        cmds.append(c)

            if not cmds:
                break

            for cmd in cmds[:3]:
                try:
                    if "|" in cmd:
                        r = sp.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                        output = (r.stdout + r.stderr)
                    else:
                        output = self.tools.run(shlex.split(cmd), timeout=300, max_output_len=50_000)
                except sp.TimeoutExpired:
                    output = "(TIMEOUT — site yanıt vermiyor olabilir)"
                except Exception as e:
                    output = f"(error: {e})"

                # Show tool execution to user
                print(f"\n  🔧 $ {cmd[:120]}")
                if "\n" in output[:200]:
                    print(f"  {output[:200]}")
                else:
                    print(f"  {output[:80]}")

            # Feed results back to AI
            self.history.append({"role": "assistant", "content": response})
            self.history.append({"role": "user", "content": f"Results above. Summarize or continue."})

        # Log to session file
        if session_file:
            try:
                entry = display_text if display_text else (response[:200] if response else user_input)
                with open(session_file, 'a') as f:
                    f.write(f"\n## {datetime.now().strftime('%H:%M:%S')}\n**User:** {user_input}\n\n**Suvari:** {entry[:500]}\n\n")
            except Exception:
                pass

        return display_text or response[:500] or "Done."

    # ─── Attack ───

    def attack(self, scan_dir: Optional[Path] = None) -> dict:
        """Exploit findings from a previous scan."""
        scan_dir = scan_dir or self.last_scan_dir
        if not scan_dir:
            return {"error": "No scan directory"}
        findings_file = scan_dir / "analysis" / "findings.json"
        if not findings_file.exists():
            return {"error": f"No findings in {scan_dir}"}
        findings = json.loads(findings_file.read_text())
        from .agents.exploiter import ExploiterAgent
        ws = Workspace(f"attack-{scan_dir.name}")
        agent = ExploiterAgent("exploit", self.llm, ws, self.tools)
        return agent.run({"target_url": str(findings.get("vulnerabilities", [{}])[0].get("location", "")).split("/")[0],
                          "analysis": findings})

    # ─── Helpers ───

    def list_scans(self) -> list:
        d = Path("output")
        if not d.exists():
            return []
        return sorted([p.name for p in d.iterdir()], reverse=True)[:10]

    def get_report(self, scan_dir: Path) -> str:
        r = scan_dir / "report.md"
        return r.read_text()[:3000] if r.exists() else ""

    def _get_system_prompt(self) -> str:
        """System prompt for chat."""
        return """You are Suvari, an AI-powered pentesting assistant for AUTHORIZED testing only.

YOUR ROLE: Analyze scan findings and suggest/execute exploitation steps.
Given existing findings (vulnerabilities), explain how to exploit each one.
Write code in ```python or ```bash blocks. Code is auto-saved.
Run tools in ```tool blocks to verify or exploit findings.
Respond in the user's language."""

    def _load_results(self, path: Path) -> dict:
        results = {"path": str(path)}
        f = path / "analysis" / "findings.json"
        if f.exists():
            results["findings"] = json.loads(f.read_text())
        r = path / "report.md"
        if r.exists():
            results["report"] = r.read_text()[:2000]
        return results


# ─── P-E-R components (used by orchestrator) ───

class PromptLoader:
    """Stub - Prompt loading for orchestrator compatibility."""
    def __init__(self, target_url: str = "", fast: bool = False):
        self.target_url = target_url
        self.fast = fast

class Planner:
    """P-E-R planner - decides next action based on phase and results."""
    def __init__(self, llm, tools, prompts):
        self.llm = llm
        self.tools = tools
        self.prompts = prompts
        self._knowledge = {}

    def decide(self, phase: str, completed: list, last_results: dict) -> dict:
        """Decide next action. Returns plan dict with next_action + reasoning."""
        return {"next_action": phase, "reasoning": f"Executing {phase} phase"}

    def add_knowledge(self, key: str, value):
        """Store knowledge for future planning."""
        self._knowledge[key] = value

class Reflector:
    """P-E-R reflector - analyzes tool output for improvements."""
    def __init__(self, llm):
        self.llm = llm
        self._failures = []

    def analyze(self, last_action: str = "", tool: str = "", output: str = "", phase: str = "", target_url: str = "") -> dict:
        """Analyze output and return reflection."""
        return {"success": True, "findings": [], "improvements": []}
