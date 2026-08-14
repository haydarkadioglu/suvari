


   

from typing import Optional

from pathlib import Path

from datetime import datetime

from suvari.llm import LLMClient

from suvari.bus import FindingsBus

from suvari.workspace import Workspace

from suvari.tools.runner import ToolRunner

from suvari.config import load_config

import re, json, shlex, subprocess as sp

class SuvariCore:

                                                                      

    def __init__(self):

        cfg = load_config()

        self.llm = LLMClient(provider=cfg.get("provider", "deepseek"), model=cfg.get("model"))

        self.tools = ToolRunner()

        self.bus = FindingsBus()

        self.history = []

        self.last_scan_dir: Optional[Path] = None

    def scan(self, url: str, fast: bool = False) -> dict:

                                     

        from .orchestrator import SuvariOrchestrator

        ws = Workspace(url)

        orch = SuvariOrchestrator(target_url=url, workspace=ws, fast=fast)

        orch.run()

        self.last_scan_dir = ws.path

        return self._load_results(ws.path)

    def recon(self, url: str) -> dict:

                                      

        from .agents.recon import ReconAgent

        ws = Workspace("recon")

        agent = ReconAgent("recon", self.llm, ws, self.tools)

        return agent.run({"target_url": url})

    def chat(self, user_input: str, session_file: Optional[Path] = None, max_rounds: int = 20) -> str:

                                                                              

        from .agents.exploiter import ExploiterAgent

        SYSTEM_PROMPT = self._get_system_prompt()

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

        path_match = re.search(r'(/home/[^\s]*output/[^\s]+)', user_input)

        raw_path = Path(path_match.group(1)) if path_match else None

        target_dir = None

        if raw_path:

            if raw_path.is_dir():

                target_dir = raw_path

            elif raw_path.is_file():

                target_dir = raw_path.parent

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

                print(f"\n  🔧 $ {cmd[:120]}")

                if "\n" in output[:200]:

                    print(f"  {output[:200]}")

                else:

                    print(f"  {output[:80]}")

            self.history.append({"role": "assistant", "content": response})

            self.history.append({"role": "user", "content": f"Results above. Summarize or continue."})

        if session_file:

            try:

                entry = display_text if display_text else (response[:200] if response else user_input)

                with open(session_file, 'a') as f:

                    f.write(f"\n## {datetime.now().strftime('%H:%M:%S')}\n**User:** {user_input}\n\n**Suvari:** {entry[:500]}\n\n")

            except Exception:

                pass

        return display_text or response[:500] or "Done."

    def attack(self, scan_dir: Optional[Path] = None) -> dict:

                                                    

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

    def list_scans(self) -> list:

        d = Path("output")

        if not d.exists():

            return []

        return sorted([p.name for p in d.iterdir()], reverse=True)[:10]

    def get_report(self, scan_dir: Path) -> str:

        r = scan_dir / "report.md"

        return r.read_text()[:3000] if r.exists() else ""

    def _get_system_prompt(self) -> str:

                                     

        return




                                  

    def _load_results(self, path: Path) -> dict:

        results = {"path": str(path)}

        f = path / "analysis" / "findings.json"

        if f.exists():

            results["findings"] = json.loads(f.read_text())

        r = path / "report.md"

        if r.exists():

            results["report"] = r.read_text()[:2000]

        return results

class PromptLoader:

                                                               

    def __init__(self, target_url: str = "", fast: bool = False):

        self.target_url = target_url

        self.fast = fast

class Planner:

                                                                             

    def __init__(self, llm, tools, prompts):

        self.llm = llm

        self.tools = tools

        self.prompts = prompts

        self._knowledge = {}

        self._phase_history = []

        self._adaptive_strategy = None

    def decide(self, phase: str, completed: list, last_results: dict) -> dict:

                                                                                       

        context = self._build_decision_context(phase, completed, last_results)

        try:

            system_prompt = self._get_planner_prompt()

            response = self.llm.chat(

                messages=[

                    {"role": "system", "content": system_prompt},

                    {"role": "user", "content": context}

                ],

                temperature=0.2,

                max_tokens=512

            )

            plan = self._parse_ai_plan(response, phase)

            plan["ai_decided"] = True

        except Exception as e:

            plan = self._fallback_decision(phase, completed, last_results)

            plan["ai_decided"] = False

            plan["fallback_reason"] = str(e)

        self._phase_history.append({

            "phase": phase,

            "plan": plan,

            "context_summary": self._summarize_context(last_results)

        })

        return plan

    def _build_decision_context(self, phase: str, completed: list, last_results: dict) -> str:

                                                                 

        recon_summary = ""

        if "recon_results" in last_results:

            recon = last_results["recon_results"]

            techs = recon.get("whatweb", "")[:300]

            ports = recon.get("nmap", "")[:200]

            recon_summary = f"Recon found: Tech={techs}, Ports={ports}"

        scan_summary = ""

        if "scan_results" in last_results:

            scan = last_results["scan_results"]

            vulns = scan.get("vulnerabilities", [])[:3]

            if vulns:

                scan_summary = f"Scan found {len(vulns)} vulns: " + ", ".join([v.get("type", "") for v in vulns])

        avail_tools = list(self.tools.available_tools().keys())[:15]

        context = f"""Current Phase: {phase}
Completed Phases: {', '.join(completed)}
{recon_summary}
{scan_summary}
Available Tools: {', '.join(avail_tools)}
Target: {last_results.get('target_url', 'unknown')}
Based on this context, decide the optimal next action."""

        return context

    def _get_planner_prompt(self) -> str:

                                           

        return











    

    def _parse_ai_plan(self, response: str, default_phase: str) -> dict:

                                                     

        import json

        import re

        json_match = re.search(r'\{[^}]*\}', response, re.DOTALL)

        if json_match:

            try:

                plan = json.loads(json_match.group())

                return {

                    "next_action": plan.get("next_action", default_phase),

                    "reasoning": plan.get("reasoning", "AI-selected action"),

                    "priority": plan.get("priority", "medium"),

                    "expected_outcome": plan.get("expected_outcome", ""),

                }

            except json.JSONDecodeError:

                pass

        return {

            "next_action": default_phase,

            "reasoning": "Default action (JSON parse failed)",

            "priority": "medium",

            "expected_outcome": ""

        }

    def _fallback_decision(self, phase: str, completed: list, last_results: dict) -> dict:

                                                            

        if phase == "recon":

            return {

                "next_action": "recon",

                "reasoning": "Initial reconnaissance required",

                "priority": "high",

                "expected_outcome": "Target profiling"

            }

        elif phase == "scan":

            if "recon_results" not in last_results:

                return {

                    "next_action": "recon",

                    "reasoning": "Need more recon before scanning",

                    "priority": "high",

                    "expected_outcome": "Complete recon first"

                }

            return {

                "next_action": "scan",

                "reasoning": "Proceeding with vulnerability scan",

                "priority": "high",

                "expected_outcome": "Vulnerability detection"

            }

        elif phase == "analyze":

            return {

                "next_action": "analyze",

                "reasoning": "Analyzing scan results with AI",

                "priority": "medium",

                "expected_outcome": "Prioritized findings"

            }

        elif phase == "exploit":

            return {

                "next_action": "exploit",

                "reasoning": "Attempting exploitation of high-severity findings",

                "priority": "medium",

                "expected_outcome": "PoC exploits"

            }

        return {

            "next_action": phase,

            "reasoning": "Default phase execution",

            "priority": "low",

            "expected_outcome": ""

        }

    def add_knowledge(self, key: str, value):

                                                                                  

        self._knowledge[key] = value

        if len(self._knowledge) > 3:

            self._update_adaptive_strategy()

    def _update_adaptive_strategy(self):

                                                                                

        try:

            knowledge_text = "\n".join([f"- {k}: {v}" for k, v in self._knowledge.items()])

            prompt = f"""Based on these findings, suggest an adaptive strategy adjustment:
{knowledge_text}
Respond with one strategic adjustment in JSON: { "adjustment": "...", "reason": "..."} """

            response = self.llm.chat(

                messages=[{"role": "user", "content": prompt}],

                temperature=0.1,

                max_tokens=256

            )

            import json, re

            match = re.search(r'\{[^}]*\}', response)

            if match:

                self._adaptive_strategy = json.loads(match.group())

        except Exception:

            pass

    def get_adaptive_strategy(self) -> dict:

                                            

        return self._adaptive_strategy or {"adjustment": "Standard scanning", "reason": "No adjustments yet"}

    def _summarize_context(self, results: dict) -> str:

                                                                    

        parts = []

        if "recon_results" in results:

            parts.append("recon_done")

        if "scan_results" in results:

            vulns = results["scan_results"].get("vulnerabilities", [])

            if isinstance(vulns, list):

                parts.append(f"{len(vulns)}_vulns")

        return "_".join(parts) or "no_data"

class Reflector:

                                                                                          

    def __init__(self, llm):

        self.llm = llm

        self._failures = []

        self._success_patterns = []

        self._reflection_count = 0

    def analyze(self, last_action: str = "", tool: str = "", output: str = "", 

                phase: str = "", target_url: str = "") -> dict:

                                                                                        

        self._reflection_count += 1

        try:

            reflection = self._ai_reflect(last_action, tool, output, phase, target_url)

            if reflection.get("success"):

                self._success_patterns.append({

                    "tool": tool,

                    "phase": phase,

                    "findings_count": len(reflection.get("findings", []))

                })

            if not reflection.get("success"):

                self._failures.append({

                    "tool": tool,

                    "phase": phase,

                    "output_snippet": output[:200],

                    "timestamp": self._reflection_count

                })

            if "ai_error" not in reflection:

                reflection["ai_powered"] = True

            else:

                reflection["ai_powered"] = False

            return reflection

        except Exception as e:

            basic = self._basic_reflect(last_action, tool, output, phase)

            basic["exception"] = str(e)

            return basic

    def _ai_reflect(self, last_action: str, tool: str, output: str, 

                    phase: str, target_url: str) -> dict:

                                                                  

        prompt = f"""Analyze this security tool output and provide structured feedback:
Tool: {tool}
Phase: {phase}
Target: {target_url}
Output (first 1500 chars):
{output[:1500]}
Extract:
1. Was the tool successful? (yes/no)
2. What vulnerabilities or findings were discovered?
3. What improvements would you suggest for next iteration?
4. Should we run additional follow-up tools? Which ones?
Respond in JSON:
{ 
  "success": true/false,
  "findings": [{ "type": "...", "severity": "...", "detail": "..."} ],
  "improvements": ["suggestion1", "suggestion2"],
  "follow_up_tools": ["tool1", "tool2"],
  "confidence": 0.0-1.0
} """

        try:

            response = self.llm.chat(

                messages=[{"role": "user", "content": prompt}],

                temperature=0.1,

                max_tokens=768

            )

            import json, re

            json_match = re.search(r'\{[^}]*\}', response, re.DOTALL)

            if json_match:

                result = json.loads(json_match.group())

                result.setdefault("success", True)

                result.setdefault("findings", [])

                result.setdefault("improvements", [])

                result.setdefault("follow_up_tools", [])

                result.setdefault("confidence", 0.5)

                return result

        except Exception:

            pass

        return {

            "success": True,

            "findings": [],

            "improvements": [],

            "follow_up_tools": [],

            "confidence": 0.5,

            "ai_error": "JSON parse failed"

        }

    def _basic_reflect(self, last_action: str, tool: str, output: str, phase: str) -> dict:

                                                           

        success_indicators = ["found", "detected", "ok", "success", "completed"]

        failure_indicators = ["error", "failed", "timeout", "unreachable", "denied"]

        output_lower = output.lower()

        success_score = sum(1 for ind in success_indicators if ind in output_lower)

        failure_score = sum(1 for ind in failure_indicators if ind in output_lower)

        success = success_score > failure_score

        findings = []

        if "critical" in output_lower:

            findings.append({"type": "critical_issue", "severity": "CRITICAL", "detail": "Critical keyword detected"})

        if "vulnerability" in output_lower:

            findings.append({"type": "vulnerability", "severity": "HIGH", "detail": "Vulnerability keyword detected"})

        return {

            "success": success,

            "findings": findings,

            "improvements": [],

            "follow_up_tools": [],

            "ai_powered": False

        }

    def get_learning_summary(self) -> dict:

                                                               

        return {

            "total_reflections": self._reflection_count,

            "successful_runs": len(self._success_patterns),

            "failed_runs": len(self._failures),

            "success_rate": len(self._success_patterns) / max(1, self._reflection_count),

            "common_failures": self._failures[-5:]

        }
