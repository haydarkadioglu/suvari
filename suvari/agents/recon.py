"""
Recon Agent — gathers information about the target.
Shows real-time tool execution with elapsed time.
"""

import time
from urllib.parse import urlparse, urlunparse
from .base import BaseAgent, fmt_time


def clean_url(url: str) -> str:
    """Remove URL fragments (#) that break CLI tools."""
    parsed = urlparse(url)
    if parsed.fragment:
        parsed = parsed._replace(fragment="")
        return urlunparse(parsed)
    return url


class ReconAgent(BaseAgent):
    """Gathers target information: technology, ports, headers."""

    def run(self, context: dict) -> dict:
        url = clean_url(context["target_url"])
        self.log(f"🌐 Reconnaissance: {url}")

        results = {}
        total_start = time.time()

        # 1. whatweb — technology fingerprinting
        if self.tools.check_tool("whatweb"):
            self.log(f"  🛠️  whatweb — Technology fingerprinting")
            t0 = time.time()
            output = self.tools.run(["whatweb", "-v", url], timeout=60)
            self.log(f"     ✅ whatweb done in {fmt_time(time.time() - t0)}")
            self.ws.save_result("recon", "whatweb", output)
            results["whatweb"] = output
        else:
            results["whatweb"] = "(whatweb not installed)"

        # 2. curl — response headers
        self.log(f"  🛠️  curl — HTTP header analysis")
        t0 = time.time()
        headers = self.tools.run(
            ["curl", "-sI", "-L", url, "--max-time", "15"], timeout=20
        )
        self.log(f"     ✅ curl done in {fmt_time(time.time() - t0)}")
        self.ws.save_result("recon", "headers", headers)
        results["headers"] = headers

        # 3. nmap — quick port scan
        if self.tools.check_tool("nmap"):
            self.log(f"  🛠️  nmap — Quick port scan")
            host = url.split("://")[-1].split("/")[0]
            t0 = time.time()
            nmap = self.tools.run(
                ["nmap", "-T4", "-F", "--open", host], timeout=120
            )
            self.log(f"     ✅ nmap done in {fmt_time(time.time() - t0)}")
            self.ws.save_result("recon", "nmap", nmap)
            results["nmap"] = nmap
        else:
            results["nmap"] = "(nmap not installed)"

        # 4. robots.txt check
        self.log(f"  🛠️  curl — robots.txt check")
        t0 = time.time()
        robots = self.tools.run(
            ["curl", "-sL", f"{url.rstrip('/')}/robots.txt", "--max-time", "10"], timeout=15
        )
        self.log(f"     ✅ robots.txt done in {fmt_time(time.time() - t0)}")
        self.ws.save_result("recon", "robots", robots)
        results["robots"] = robots

        # 5. curl — common paths check
        self.log(f"  🛠️  curl — Common path check")
        t0 = time.time()
        common_paths = ["/.git/config", "/.env", "/sitemap.xml", "/crossdomain.xml"]
        findings = []
        for path in common_paths:
            out = self.tools.run(
                ["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code}",
                 f"{url.rstrip('/')}{path}", "--max-time", "5"], timeout=10
            )
            if out.strip() not in ("404", "301", "302", "403", "(error)", "(empty)"):
                findings.append(f"{path}: {out.strip()}")
        common_result = "\n".join(findings) if findings else "No exposed files found"
        self.log(f"     ✅ common path check done in {fmt_time(time.time() - t0)}")
        self.ws.save_result("recon", "common_paths", common_result)
        results["common_paths"] = common_result

        total = fmt_time(time.time() - total_start)
        self.log(f"✅ Recon complete in {total}")
        results["_recon_time"] = total
        return results
