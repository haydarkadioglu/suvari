"""
Scanner Agent — vulnerability scanning with smart tool selection.
Uses rule-based tech detection to pick the best tools, shows real-time progress.
"""

import time
from datetime import timedelta
from .base import BaseAgent, fmt_time
from ..scanner_selector import select_tools


class ScannerAgent(BaseAgent):
    """Vulnerability scanning — smart tool selection based on target tech."""

    # Known tools that run in recon (skip these in scanner)
    RECON_TOOLS = {"whatweb"}

    def run(self, context: dict) -> dict:
        url = context["target_url"]
        recon_results = context.get("recon_results", {})
        fast = context.get("fast", False)

        self.log(f"🔍 Scanning: {url}")
        avail = self.tools.available_tools()

        # Smart tool selection
        tool_plan = select_tools(
            available=avail,
            recon_results=recon_results,
            fast=fast,
            verbose=self.verbose,
        )

        # Filter out tools already run in recon
        tool_plan = [t for t in tool_plan if t[0] not in self.RECON_TOOLS]

        if not tool_plan:
            self.log("  ⚠️ No tools available — using nuclei as fallback")
            if "nuclei" in avail:
                tool_plan = [("nuclei", ["nuclei", "-u", url, "-silent", "-severity", "critical,high,medium"], "Fallback scan", 60)]

        results = {}
        total_start = time.time()
        tools_run = 0
        max_tools = 3 if fast else 8  # Fast: max 3, Normal: max 8

        for tool_name, args, reason, max_time in tool_plan:
            if tools_run >= max_tools:
                remaining = [t[0] for t in tool_plan[tools_run:]]
                if remaining:
                    self.log(f"  ⏭️  Max tools reached ({max_tools}), skipping: {', '.join(remaining)}")
                break

            # Build command
            cmd = self._build_cmd(tool_name, args, url)

            # Run
            self.log(f"  🛠️  {tool_name} — {reason}")
            tool_start = time.time()
            output = self.tools.run(cmd, timeout=max_time + 30)
            elapsed = time.time() - tool_start

            elapsed_str = fmt_time(elapsed)
            status = "✅" if not output.startswith("(") else "⚠️"
            self.log(f"     {status} {tool_name} done in {elapsed_str}")

            self.ws.save_result("scans", tool_name, output)
            results[tool_name] = output
            results[f"{tool_name}_time"] = elapsed_str
            tools_run += 1

        total_time = str(timedelta(seconds=int(time.time() - total_start)))
        self.log(f"✅ Scan complete in {total_time}")
        results["_total_time"] = total_time
        return results

    def _build_cmd(self, tool_name: str, args: list, url: str) -> list:
        """Build the command list for a given tool."""
        builders = {
            "sqlmap": lambda: args + ["-u", url],
            "nikto": lambda: args + [url],
            "nmap": lambda: args + [url.split("://")[-1].split("/")[0]],
            "gobuster": lambda: args + ["-u", url],
            "ffuf": lambda: args + ["-u", url],
            "wpscan": lambda: args + ["--url", url],
            "httpx": lambda: args + ["-u", url],
            "curl": lambda: args + [url],
        }
        builder = builders.get(tool_name)
        if builder:
            return builder()
        return args + ["-u", url]
