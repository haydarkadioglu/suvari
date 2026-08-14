


   

import time

import json

from typing import Optional

from dataclasses import dataclass, field

from suvari.llm import LLMClient

from suvari.tools.runner import ToolRunner

from suvari.workspace import Workspace

from suvari.prompt_loader import PromptLoader

@dataclass

class CausalStep:

                                            

    tool: str

    args: list

    reason: str

    depends_on: list

    timeout: int = 60

    output: str = ""

    error: str = ""

    duration: float = 0.0

    findings: list = field(default_factory=list)

CAUSAL_PROMPT =


















   





class CausalChain:

                                                                     

    def __init__(self, url: str, llm: LLMClient, tools: ToolRunner, workspace: Workspace,

                 max_steps: int = 12):

        self.url = url

        self.llm = llm

        self.tools = tools

        self.ws = workspace

        self.max_steps = max_steps

        self.steps: list[CausalStep] = []

        self.stop_reason = ""

    def run(self) -> dict:

                                                              

        self.log(f"Causal chain: {self.max_steps} steps max")

        for i in range(self.max_steps):

            step = self._decide()

            if step is None:

                self.log(f"  Analysis complete: {self.stop_reason}")

                break

            self.log(f"  Step {i+1}: {step.tool} — {step.reason[:60]}")

            t0 = time.time()

            cmd = [step.tool] + step.args

            output = self.tools.run(cmd, timeout=step.timeout)

            step.duration = time.time() - t0

            step.output = output[:3000]

            findings = self._extract_findings(step.tool, output)

            step.findings = findings

            name = f"{i+1:02d}_{step.tool}"

            self.ws.save_result("chain", name, f"# Step {i+1}: {step.tool}\n## Reason\n{step.reason}\n## Output\n{output[:5000]}")

            if findings:

                self.ws.save_json("chain", f"{name}_findings", findings)

            self.steps.append(step)

            if findings:

                for f in findings[:2]:

                    self.log(f"    -> {f.get('type','?')}: {f.get('detail','')[:60]}")

        all_findings = []

        for s in self.steps:

            all_findings.extend(s.findings)

        result = {

            "total_steps": len(self.steps),

            "duration": sum(s.duration for s in self.steps),

            "vulnerabilities": self._aggregate_vulns(all_findings),

            "steps": [

                {"tool": s.tool, "reason": s.reason, "duration": s.duration, "findings": len(s.findings)}

                for s in self.steps

            ],

        }

        self.ws.save_json("analysis", "chain_findings", result)

        return result

    def _decide(self) -> Optional[CausalStep]:

                                                            

        state = self._build_state()

        history = self._build_history()

        avail = self.tools.available_tools()

        tool_names = ", ".join(sorted(avail.keys()))

        prompt = CAUSAL_PROMPT.format(

            state=state or "Initial scan. No data yet.",

            tools=tool_names,

            history=history or "No previous steps.",

        )

        try:

            text = self.llm.chat(

                messages=[{"role": "user", "content": prompt}],

                temperature=0.2,

                max_tokens=256,

            )

        except Exception as e:

            self.stop_reason = f"AI unavailable: {e}"

            return None

        clean = text.strip()

        if clean.upper().startswith("DONE"):

            self.stop_reason = clean[4:].strip() or "AI analysis complete"

            return None

        tool = self._extract_field(clean, "TOOL")

        if not tool:

            self.stop_reason = "No tool specified"

            return None

        args_str = self._extract_field(clean, "ARGS") or ""

        args = args_str.split() if args_str else []

        reason = self._extract_field(clean, "REASON") or f"Step {len(self.steps)+1}"

        timeout_str = self._extract_field(clean, "TIMEOUT") or "60"

        try:

            timeout = int(timeout_str)

        except ValueError:

            timeout = 60

        if tool not in avail and tool != "curl":

            for t in avail:

                if tool in t or t in tool:

                    tool = t

                    break

            else:

                self.stop_reason = f"Tool not found: {tool}"

                return None

        return CausalStep(

            tool=tool,

            args=args,

            reason=reason,

            depends_on=[s.tool for s in self.steps[-3:]],

            timeout=min(timeout, 120),

        )

    def _extract_field(self, text: str, field: str) -> str:

                                                   

        for line in text.split("\n"):

            line = line.strip()

            if line.upper().startswith(field + ":"):

                return line[len(field)+1:].strip()

            if line.upper().startswith(field + " "):

                return line[len(field)+1:].strip()

        return ""

    def _build_state(self) -> str:

                                                            

        if not self.steps:

            return ""

        parts = []

        for s in self.steps[-5:]:

            parts.append(f"{s.tool}: {s.reason[:80]}")

            if s.findings:

                for f in s.findings[:2]:

                    parts.append(f"  -> {f.get('detail','')[:80]}")

        return "\n".join(parts)

    def _build_history(self) -> str:

                                 

        if not self.steps:

            return ""

        return "\n".join([

            f"Step {i+1}: {s.tool} ({s.duration:.0f}s) - {s.reason[:60]}"

            for i, s in enumerate(self.steps)

        ])

    def _extract_findings(self, tool: str, output: str) -> list:

                                                         

        findings = []

        out_lower = output.lower()

        if tool == "nmap" or tool == "masscan":

            for line in output.split("\n"):

                if "/tcp" in line or "/udp" in line:

                    parts = line.strip().split()

                    if len(parts) >= 2:

                        findings.append({

                            "type": "port",

                            "detail": parts[0],

                            "raw": line.strip()[:100],

                        })

        if tool == "whatweb":

            for line in output.split("\n"):

                if "[" in line and "]" in line:

                    findings.append({

                        "type": "technology",

                        "detail": line.strip()[:100],

                        "raw": line.strip(),

                    })

        if tool == "nuclei":

            for line in output.split("\n"):

                if "[critical]" in out_lower or "[high]" in out_lower or "[medium]" in out_lower:

                    findings.append({

                        "type": "vulnerability",

                        "detail": line.strip()[:100],

                        "raw": line.strip(),

                    })

        if tool == "curl":

            for line in output.split("\n"):

                if "access-control" in out_lower:

                    findings.append({

                        "type": "cors",

                        "detail": line.strip()[:100],

                        "raw": line.strip(),

                    })

                if "x-frame-options" not in out_lower and "content-security-policy" not in out_lower:

                    findings.append({

                        "type": "missing_header",

                        "detail": "Security headers missing",

                    })

        return findings[:5]

    def _aggregate_vulns(self, findings: list) -> list:

                                                             

        vulns = []

        for f in findings:

            if f["type"] == "vulnerability":

                vulns.append({

                    "severity": "HIGH" if "[critical]" in f.get("raw","").lower() else "MEDIUM",

                    "type": f.get("detail","")[:80],

                    "location": self.url,

                    "source": "causal_chain",

                })

            elif f["type"] == "cors":

                vulns.append({

                    "severity": "HIGH",

                    "type": "Cross-Origin Resource Sharing (CORS)",

                    "location": self.url,

                    "source": "causal_chain",

                })

            elif f["type"] == "missing_header":

                vulns.append({

                    "severity": "LOW",

                    "type": f.get("detail",""),

                    "location": self.url,

                    "source": "causal_chain",

                })

        return vulns[:10]

    def log(self, msg: str):

        print(f"  {msg}")
