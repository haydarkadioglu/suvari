"""
Recon Agent — gathers information about the target.
Uses whatweb, nmap, curl for tech/port/header analysis.
"""

from .base import BaseAgent


class ReconAgent(BaseAgent):
    """Gathers target information: technology, ports, headers."""

    def run(self, context: dict) -> dict:
        url = context["target_url"]
        self.log(f"🌐 Reconnaissance starting: {url}")

        results = {}

        # 1. whatweb — technology fingerprinting
        if self.tools.check_tool("whatweb"):
            self.log("  Running whatweb...")
            output = self.tools.run(["whatweb", "-v", url], timeout=60)
            self.ws.save_result("recon", "whatweb", output)
            results["whatweb"] = output
        else:
            results["whatweb"] = "(whatweb not installed)"

        # 2. curl — response headers + basic info
        self.log("  Running curl header analysis...")
        headers = self.tools.run(
            ["curl", "-sI", "-L", url, "--max-time", "15"], timeout=20
        )
        self.ws.save_result("recon", "headers", headers)
        results["headers"] = headers

        # 3. nmap — quick port scan
        if self.tools.check_tool("nmap"):
            self.log("  Running nmap fast scan...")
            host = url.split("://")[-1].split("/")[0]
            nmap = self.tools.run(
                ["nmap", "-T4", "-F", "--open", host], timeout=120
            )
            self.ws.save_result("recon", "nmap", nmap)
            results["nmap"] = nmap
        else:
            results["nmap"] = "(nmap not installed)"

        # 4. robots.txt check
        self.log("  Checking robots.txt...")
        robots = self.tools.run(
            ["curl", "-sL", f"{url.rstrip('/')}/robots.txt", "--max-time", "10"], timeout=15
        )
        self.ws.save_result("recon", "robots", robots)
        results["robots"] = robots

        self.log("✅ Recon complete")
        return results
