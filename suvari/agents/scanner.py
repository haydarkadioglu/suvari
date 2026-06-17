"""
Scanner Agent — vulnerability scanning.
AI decides which tools to run based on recon results.
Inspired by Shannon's multi-agent approach.
"""

from .base import BaseAgent
from ..prompt_loader import PromptLoader


class ScannerAgent(BaseAgent):
    """Vulnerability scanning — AI chooses which tools to run."""

    def run(self, context: dict) -> dict:
        url = context["target_url"]
        recon_data = context.get("recon_results", {})
        fast = context.get("fast", False)

        self.log(f"🔍 Scanning starting: {url}")

        # Combine recon results
        recon_text = "\n\n".join([
            f"=== {k} ===\n{v[:2000]}"
            for k, v in recon_data.items()
            if isinstance(v, str) and v and not v.startswith("(")
        ])

        avail = self.tools.available_tools()

        # Load prompt from file
        loader = PromptLoader(url, fast)
        system_prompt = loader.render_with_shared("scanner",
            recon_data=recon_text[:3000],
            available_tools=avail,
        )

        # Ask AI: which scans to run?
        self.log("  AI planning scans...")

        try:
            scan_plan = self.llm.chat_json(
                messages=[{"role": "user", "content": system_prompt}],
                temperature=0.2,
            )
        except Exception as e:
            self.log(f"  ⚠️ AI plan error: {e}, running default scans")
            scan_plan = [{"tool": "nuclei", "args": ["-silent", "-severity", "critical,high,medium"], "reason": "default scan"}]

        # Execute the plan
        results = {}
        commands = scan_plan if isinstance(scan_plan, list) else scan_plan.get("commands", [])

        if fast:
            commands = commands[:2]

        for cmd in commands[:5]:
            tool = cmd.get("tool", cmd.get("name", ""))
            args = cmd.get("args", [])
            reason = cmd.get("reason", "")

            if not tool or not self.tools.check_tool(tool):
                self.log(f"  ⏭️ {tool} not available")
                continue

            self.log(f"  🛠️ {tool}: {reason}")

            if tool == "nuclei":
                output = self.tools.run(
                    ["nuclei", "-u", url, "-silent", "-severity", "critical,high,medium"],
                    timeout=180,
                )
            elif tool == "nikto":
                output = self.tools.run(
                    ["nikto", "-h", url, "-Tuning", "1234789"],
                    timeout=120,
                )
            elif tool == "gobuster":
                output = self.tools.run(
                    ["gobuster", "dir", "-u", url, "-w", "/usr/share/wordlists/dirb/common.txt",
                     "-t", "30", "-q"],
                    timeout=120,
                )
            elif tool == "wpscan":
                output = self.tools.run(
                    ["wpscan", "--url", url, "--no-banner", "-e", "vp,vt"],
                    timeout=180,
                )
            else:
                full_cmd = [tool] + args + [url]
                output = self.tools.run(full_cmd, timeout=120)

            self.ws.save_result("scans", tool, output)
            results[tool] = output

        self.log("✅ Scanning complete")
        return results
