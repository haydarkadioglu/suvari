"""
Scan Chain — tree-based recursive scanning and attack chains.
AI decides what to try next based on findings, drills deeper on interesting paths.
"""

import time
import json
from typing import Optional
from .llm import LLMClient
from .tools.runner import ToolRunner
from .workspace import Workspace
from .prompt_loader import PromptLoader
from .agents.base import fmt_time

CHAIN_SYSTEM_PROMPT = """You are a penetration testing strategist running a live scan chain.

Current state (findings so far):
{state}

Available tools: {tools}

Your job is to decide the NEXT action. Think like an attacker:
1. What's the most promising lead right now?
2. Should I drill deeper on an existing finding?
3. Should I try a different tool on the same target?
4. Are any findings connected? Can I chain them?
5. Is anything a dead end?

Return JSON:
{
  "action": "drill" or "new" or "chain" or "stop",
  "tool": "tool_name",
  "target": "what to target specifically",
  "args": ["arg1", "arg2"],
  "reason": "why this action",
  "confidence": "high/medium/low",
  "chain_with": ["finding_1", "finding_2"]
}

If action is "stop", scanning ends and moves to exploitation.
If action is "chain", connect findings into an attack path.
"""


class ScanNode:
    """A single node in the scan tree."""
    
    def __init__(self, tool: str, target: str, reason: str, parent: Optional["ScanNode"] = None):
        self.tool = tool
        self.target = target
        self.reason = reason
        self.parent = parent
        self.children = []
        self.output = ""
        self.status = "pending"
        self.findings = []
        self.time = 0.0
        self.depth = parent.depth + 1 if parent else 0

    def add_child(self, node: "ScanNode"):
        self.children.append(node)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "target": self.target,
            "reason": self.reason,
            "status": self.status,
            "time": self.time,
            "findings": self.findings[:3],
            "depth": self.depth,
            "children": [c.to_dict() for c in self.children],
        }


class ScanChain:
    """Tree-based scan chain execution."""

    TOOL_MAX_TIMES = {
        "nuclei": 120, "nikto": 150, "gobuster": 90, "ffuf": 90,
        "sqlmap": 210, "wpscan": 150, "httpx": 30, "curl": 15,
        "nmap": 90, "hydra": 180, "whatweb": 30, "subfinder": 60,
        "dnsenum": 60, "enum4linux": 60, "smbmap": 30,
    }

    def __init__(self, url: str, llm: LLMClient, tools: ToolRunner, workspace: Workspace,
                 fast: bool = False, max_depth: int = 3, verbose: bool = False):
        self.url = url
        self.llm = llm
        self.tools = tools
        self.ws = workspace
        self.fast = fast
        self.max_depth = max_depth
        self.verbose = verbose
        self.root = ScanNode("init", url, "Starting scan", parent=None)
        self.all_findings = []
        self.chain_log = []

    def _build_cmd(self, tool: str, args: list, target: str) -> list:
        cmd = [tool] + args
        if tool in ("nuclei", "gobuster", "ffuf", "sqlmap", "httpx"):
            cmd += ["-u", target]
        elif tool in ("nikto", "curl"):
            cmd += [target]
        elif tool == "wpscan":
            cmd += ["--url", target]
        elif tool == "nmap":
            cmd += [target.split("://")[-1].split("/")[0]]
        elif tool in ("subfinder", "dnsenum"):
            cmd += [target.split("://")[-1].split("/")[0]]
        elif tool in ("enum4linux", "smbmap"):
            cmd += [target.split("://")[-1].split("/")[0]]
        elif tool == "hydra":
            pass  # Hydra needs specific args
        return cmd

    def run(self) -> list:
        """Run the scan chain. Returns all findings."""
        
        # Phase 1: Initial recon tools
        initial_tools = [
            ("whatweb", [], "Technology fingerprinting"),
            ("curl", ["-sI"], "HTTP header analysis"),
        ]
        if self.tools.check_tool("nmap"):
            initial_tools.append(("nmap", ["-T4", "-F", "--open"], "Quick port scan"))

        for tool, args, reason in initial_tools:
            if not self.tools.check_tool(tool):
                continue
            node = ScanNode(tool, self.url, reason, self.root)
            self._execute_node(node, args)
            self.root.add_child(node)

        # Phase 2: AI-driven chain
        max_rounds = 5 if self.fast else 12
        for round_num in range(max_rounds):
            decision = self._ai_decide()
            if decision.get("action") == "stop":
                self.chain_log.append(f"[STOP] AI decided to end scanning")
                break

            tool = decision.get("tool", "")
            if not tool or not self.tools.check_tool(tool):
                continue

            target = decision.get("target", self.url)
            if not target.startswith("http"):
                target = self.url.rstrip("/") + "/" + target.lstrip("/")

            args = decision.get("args", [])
            reason = decision.get("reason", "AI decision")

            # Find the right parent node for tree building
            parent = self._find_parent_for_tool(tool)
            node = ScanNode(tool, target, reason, parent)
            parent.add_child(node)

            self.chain_log.append(f"[{round_num+1}/{max_rounds}] {tool} on {target}: {reason}")
            
            if self.verbose:
                print(f"  Chain: {tool} -> {target} ({reason[:60]})")

            self._execute_node(node, args)

            # If findings found, consider drilling deeper
            if node.findings and node.depth < self.max_depth:
                for finding in node.findings[:2]:
                    drill_node = ScanNode("drill", finding, f"Deeper on: {finding[:60]}", node)
                    self._execute_drill(drill_node, finding)
                    if drill_node.children:
                        node.add_child(drill_node)

        return self.all_findings

    def _execute_node(self, node: ScanNode, args: list):
        """Execute a single scan node."""
        max_time = self.TOOL_MAX_TIMES.get(node.tool, 60)
        cmd = self._build_cmd(node.tool, args, node.target)

        t0 = time.time()
        output = self.tools.run(cmd, timeout=max_time)
        elapsed = time.time() - t0

        node.time = elapsed
        node.output = output[:500]
        node.status = "OK" if not output.startswith("(") else "ERROR"

        self.ws.save_result("chain", f"{node.tool}_{len(self.chain_log)}", output)

        # Extract findings from output (simple heuristic)
        if node.status == "OK" and len(output) > 10:
            node.findings = self._extract_findings(output, node.tool)
            self.all_findings.extend(node.findings)

    def _execute_drill(self, node: ScanNode, finding: str):
        """Execute a focused drill on a finding."""
        # Try deeper tool based on finding type
        finding_lower = finding.lower()

        if "directory" in finding_lower or "admin" in finding_lower or "backup" in finding_lower:
            if self.tools.check_tool("gobuster"):
                target = self.url.rstrip("/") + "/" + finding.split("/")[-1]
                n = ScanNode("gobuster", target, f"Deep dir scan: {finding[:40]}", node)
                self._execute_node(n, ["dir", "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "20", "-q"])
                node.add_child(n)

        if "sql" in finding_lower or "database" in finding_lower or "mysql" in finding_lower:
            if self.tools.check_tool("sqlmap"):
                n = ScanNode("sqlmap", node.target, f"SQLi check: {finding[:40]}", node)
                self._execute_node(n, ["--batch", "--random-agent", "--time-sec", "3"])
                node.add_child(n)

        if "ssh" in finding_lower or "password" in finding_lower:
            if self.tools.check_tool("hydra"):
                host = node.target.split("://")[-1].split("/")[0]
                n = ScanNode("hydra", host, f"Brute force: {finding[:40]}", node)
                self._execute_node(n, ["-l", "root", "-P", "/usr/share/wordlists/rockyou.txt.gz", "ssh"])
                node.add_child(n)

    def _ai_decide(self) -> dict:
        """Ask AI what to do next. Robust parsing: tries JSON first, then keyword fallback."""
        state_text = self._build_state()
        avail = self.tools.available_tools()
        prompt = CHAIN_SYSTEM_PROMPT.format(
            state=state_text[:2000],
            tools=", ".join(avail.keys()) or "none",
        )

        try:
            # Step 1: Try to get plain text response
            raw = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3, max_tokens=512,
            )

            # Step 2: Try JSON parsing
            text = raw.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3].strip()
            if text.startswith("json"):
                text = text[4:].strip()

            try:
                return json.loads(text)
            except json.JSONDecodeError:
                pass

            # Step 3: Keyword-based fallback
            text_lower = text.lower()
            decision = {"action": "continue", "reason": raw[:100]}

            # Check for stop signals
            if any(w in text_lower for w in ["stop", "done", "complete", "finished", "no more"]):
                decision["action"] = "stop"
                return decision

            # Extract tool name
            for tool_name in avail:
                if tool_name in text_lower:
                    decision["tool"] = tool_name
                    decision["action"] = "continue"
                    # Extract target if mentioned
                    if "target" in text_lower or "on " in text_lower:
                        decision["target"] = self.url
                    return decision

            # If we get here with no tool, stop
            decision["action"] = "stop"
            return decision

        except Exception as e:
            return {"action": "stop", "reason": f"AI error: {e}"}

    def _build_state(self) -> str:
        """Build current state summary for AI."""
        parts = [f"Target: {self.url}"]
        parts.append(f"\nFindings ({len(self.all_findings)}):")
        for f in self.all_findings[-10:]:
            parts.append(f"  - {f[:120]}")
        parts.append(f"\nChain log ({len(self.chain_log)} steps):")
        for log in self.chain_log[-5:]:
            parts.append(f"  {log}")
        return "\n".join(parts)

    def _find_parent_for_tool(self, tool: str) -> ScanNode:
        """Find the best parent node for a tool based on context."""
        if not self.root.children:
            return self.root
        # Find last successful node
        for child in reversed(self.root.children):
            if child.status == "OK":
                return child
        return self.root.children[-1] if self.root.children else self.root

    def _extract_findings(self, output: str, tool: str) -> list:
        """Extract potential findings from tool output."""
        findings = []
        lines = output.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Skip common noise
            if any(x in line for x in ["Starting", "ending", "Completed", "Copyright", "License"]):
                continue
            if len(line) < 15:
                continue
            # Check for finding-like patterns
            if any(kw in line.lower() for kw in [
                "found", "vulnerable", "cve-", "open", "exposed", "admin",
                "login", "password", "sql", "xss", "rce", "lfi", "ssrf",
                "200 ok", "301", "302", "directory listing",
            ]):
                findings.append(line[:150])
        return findings[:5]
