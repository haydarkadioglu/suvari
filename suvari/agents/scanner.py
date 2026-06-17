"""
Scanner Agent — vulnerability scanning with smart tool selection.
Uses rule-based tech detection to pick the best tools, shows real-time progress.
"""

import time
from datetime import timedelta
from .base import BaseAgent
from ..scanner_selector import select_tools, detect_tech_from_recon


class ScannerAgent(BaseAgent):
    """Vulnerability scanning — smart tool selection based on target tech."""

    def run(self, context: dict) -> dict:
        url = context["target_url"]
        recon_results = context.get("recon_results", {})
        fast = context.get("fast", False)

        self.log(f"🔍 Scanning: {url}")
        avail = self.tools.available_tools()

        # Smart tool selection (no AI call needed — rule-based)
        tool_plan = select_tools(
            available=avail,
            recon_results=recon_results,
            fast=fast,
            verbose=self.verbose,
        )

        if not tool_plan:
            self.log("  ⚠️ No tools available — using nuclei as fallback")
            if "nuclei" in avail:
                tool_plan = [("nuclei", ["nuclei", "-u", url, "-silent", "-severity", "critical,high,medium"], "Fallback scan", 60)]

        results = {}
        total_start = time.time()

        for tool_name, args, reason, max_time in tool_plan:
            # Build command: tool + args + URL
            if tool_name == "sqlmap":
                cmd = args + ["-u", url]
            elif tool_name == "nikto":
                cmd = args + [url]
            elif tool_name == "nmap":
                host = url.split("://")[-1].split("/")[0]
                cmd = args + [host]
            elif tool_name in ("gobuster", "ffuf"):
                cmd = args + ["-u", url]
            elif tool_name == "wpscan":
                cmd = args + ["--url", url]
            elif tool_name == "whatweb":
                cmd = args + [url]
            elif tool_name == "httpx":
                cmd = args + ["-u", url]
            elif tool_name == "curl":
                cmd = args + [url]
            else:
                # nuclei and others take URL directly
                cmd = args + ["-u", url]

            # Show real-time progress
            self.log(f"  🛠️  {tool_name} — {reason}")
            if self.verbose:
                print(f"     {' '.join(cmd)[:120]}")

            # Run with progress indicator
            tool_start = time.time()
            output = self.tools.run(cmd, timeout=max_time + 30)
            elapsed = time.time() - tool_start

            # Show completion
            elapsed_str = str(timedelta(seconds=int(elapsed)))
            status = "✅" if not output.startswith("(") else "⚠️"
            self.log(f"     {status} {tool_name} done in {elapsed_str}")

            self.ws.save_result("scans", tool_name, output)
            results[tool_name + "_time"] = elapsed_str
            results[tool_name] = output

            # Fast mode: exit after first 2 successful tools
            if fast and len(results) >= 4:  # 2 tools + 2 time entries
                remaining = [t[0] for t in tool_plan[len(results)//2:]]
                if remaining:
                    self.log(f"  ⏭️  Fast mode: skipping {', '.join(remaining)}")
                break

        total_time = str(timedelta(seconds=int(time.time() - total_start)))
        self.log(f"✅ Scan complete in {total_time}")
        results["_total_time"] = total_time
        return results
