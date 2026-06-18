"""
BugBounty Agent — specialized bug bounty hunting workflow.
Inspired by HexStrike's BugBountyWorkflowManager.

Focused recon + vulnerability hunting + OSINT for bug bounty targets.
"""

from .base import BaseAgent


class BugBountyAgent(BaseAgent):
    """Bug bounty focused reconnaissance and hunting."""

    def run(self, context: dict) -> dict:
        url = context["target_url"]
        from rich.console import Console
        console = Console()
        console.print(f"  [dim]BugBounty: {url}[/dim]")

        results = {}
        domain = url.split("://")[-1].split("/")[0]

        # Phase 1: Subdomain enumeration
        console.print(f"  Phase 1: Subdomain enumeration")
        subdomains = self._enum_subdomains(domain)
        results["subdomains"] = subdomains
        console.print(f"    [OK] {len(subdomains)} subdomains")

        # Phase 2: URL discovery
        console.print(f"  Phase 2: URL discovery")
        urls = self._discover_urls(domain)
        results["urls"] = urls
        console.print(f"    [OK] {len(urls)} URLs")

        # Phase 3: Parameter discovery
        console.print(f"  Phase 3: Parameter discovery")
        params = self._discover_params(url)
        results["params"] = params
        console.print(f"    [OK] {len(params)} params")

        # Phase 4: Technology fingerprinting
        console.print(f"  Phase 4: Technology")
        tech = self._fingerprint_tech(url)
        results["technology"] = tech
        console.print(f"    [OK] {len(tech)} techs")

        console.print(f"  Done: {len(subdomains)} subdomains, {len(urls)} URLs")
        return results

    def _enum_subdomains(self, domain: str) -> list:
        """Enumerate subdomains using available tools."""
        found = set()

        if self.tools.check_tool("subfinder"):
            out = self.tools.run(["subfinder", "-silent", "-d", domain], timeout=60)
            for line in out.splitlines():
                line = line.strip()
                if line and not line.startswith("("):
                    found.add(line)

        if self.tools.check_tool("dnsenum"):
            out = self.tools.run(["dnsenum", "--enum", domain, "--noreverse"], timeout=60)
            for line in out.splitlines():
                if ":" in line and not line.startswith("("):
                    found.add(line.split(":")[-1].strip())

        return sorted(found)

    def _discover_urls(self, domain: str) -> list:
        """Discover URLs from various sources."""
        found = set()

        if self.tools.check_tool("gau"):
            out = self.tools.run(["gau", "--subs", domain], timeout=60)
            for line in out.splitlines()[:200]:
                line = line.strip()
                if line and not line.startswith("("):
                    found.add(line)

        if self.tools.check_tool("waybackurls"):
            out = self.tools.run(["waybackurls", domain], timeout=60)
            for line in out.splitlines()[:200]:
                line = line.strip()
                if line and not line.startswith("("):
                    found.add(line)

        return sorted(found)

    def _discover_params(self, url: str) -> list:
        """Discover URL parameters."""
        found = []
        if self.tools.check_tool("arjun"):
            out = self.tools.run(["arjun", "-u", url, "--quiet"], timeout=120)
            for line in out.splitlines():
                if "parameters" in line.lower() or "found" in line.lower():
                    found.append(line.strip())
        return found

    def _fingerprint_tech(self, url: str) -> list:
        """Identify technology stack."""
        techs = []
        if self.tools.check_tool("httpx"):
            out = self.tools.run(
                ["httpx", "-u", url, "-silent", "-tech-detect", "-sc", "-title"],
                timeout=30
            )
            if out and not out.startswith("("):
                techs.append(out[:500])
        if self.tools.check_tool("wafw00f"):
            out = self.tools.run(["wafw00f", url], timeout=30)
            if out and "behind" in out.lower():
                techs.append(f"WAF detected")
        return techs
