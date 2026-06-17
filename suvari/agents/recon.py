"""
Recon Agent — gathers information about the target.
Shows real-time tool execution with elapsed time.
"""

import time
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from .base import BaseAgent, fmt_time


def clean_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.fragment:
        parsed = parsed._replace(fragment="")
        return urlunparse(parsed)
    return url


# Key source files to read in white-box mode
SOURCE_FILES = [
    "package.json", "requirements.txt", "Pipfile", "Gemfile",
    "composer.json", "go.mod", "Cargo.toml",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env.example", ".env", "config.js", "config.py",
    "app.js", "app.py", "index.js", "server.js", "main.py",
    "routes/", "controllers/", "api/", "middleware/",
]


class ReconAgent(BaseAgent):
    """Gathers target information: technology, ports, headers, source code."""

    def run(self, context: dict) -> dict:
        url = clean_url(context["target_url"])
        self.log(f" Reconnaissance: {url}")

        results = {}
        total_start = time.time()

        # 1. whatweb — technology fingerprinting
        if self.tools.check_tool("whatweb"):
            self.log(f"  whatweb — Technology fingerprinting")
            t0 = time.time()
            output = self.tools.run(["whatweb", "-v", url], timeout=60)
            self.log(f"     [+] whatweb done in {fmt_time(time.time() - t0)}")
            self.ws.save_result("recon", "whatweb", output)
            results["whatweb"] = output
        else:
            results["whatweb"] = "(whatweb not installed)"

        # 2. curl — response headers
        self.log(f"  curl — HTTP header analysis")
        t0 = time.time()
        headers = self.tools.run(
            ["curl", "-sI", "-L", url, "--max-time", "15"], timeout=20
        )
        self.log(f"     [+] curl done in {fmt_time(time.time() - t0)}")
        self.ws.save_result("recon", "headers", headers)
        results["headers"] = headers

        # 3. nmap — port scan
        if self.tools.check_tool("nmap"):
            host = url.split("://")[-1].split("/")[0]
            is_server = context.get("server_scan", False)
            if is_server:
                self.log(f"  nmap — Full port scan + service detection")
                t0 = time.time()
                nmap = self.tools.run(
                    ["nmap", "-sV", "-p-", "--open", host], timeout=300
                )
            else:
                self.log(f"  nmap — Quick port scan")
                t0 = time.time()
                nmap = self.tools.run(
                    ["nmap", "-T4", "-F", "--open", host], timeout=120
                )
            self.log(f"     [+] nmap done in {fmt_time(time.time() - t0)}")
            self.ws.save_result("recon", "nmap", nmap)
            results["nmap"] = nmap
        else:
            results["nmap"] = "(nmap not installed)"

        # 4. robots.txt check
        self.log(f"  curl — robots.txt check")
        t0 = time.time()
        robots = self.tools.run(
            ["curl", "-sL", f"{url.rstrip('/')}/robots.txt", "--max-time", "10"], timeout=15
        )
        self.log(f"     [+] robots.txt done in {fmt_time(time.time() - t0)}")
        self.ws.save_result("recon", "robots", robots)
        results["robots"] = robots

        # 5. common paths check
        self.log(f"  curl — Common path check")
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
        self.log(f"     [+] common path check done in {fmt_time(time.time() - t0)}")
        self.ws.save_result("recon", "common_paths", common_result)
        results["common_paths"] = common_result

        # 6. White-box: read source code if available
        source_dir = context.get("source_dir")
        if source_dir:
            self.log(f"  source — Reading source code: {source_dir}")
            t0 = time.time()
            source_info = self._read_source_code(Path(source_dir))
            if source_info:
                self.ws.save_result("recon", "source_analysis", source_info)
                results["source_analysis"] = source_info
                lines = source_info.count("\n")
                self.log(f"     [+] Source analysis done in {fmt_time(time.time() - t0)} ({lines} lines)")

        total = fmt_time(time.time() - total_start)
        self.log(f"Recon complete in {total}")
        results["_recon_time"] = total
        results["_target"] = url
        return results

    def _read_source_code(self, source_dir: Path) -> str:
        """Read key source files for white-box analysis."""
        if not source_dir.exists():
            self.log(f"     Source directory not found: {source_dir}")
            return ""

        parts = []
        parts.append(f"=== Source: {source_dir} ===\n")

        for pattern in SOURCE_FILES:
            matches = list(source_dir.rglob(pattern))
            for fpath in matches[:5]:  # Max 5 matches per pattern
                try:
                    if fpath.is_dir():
                        # List directory contents
                        files = [p.name for p in fpath.iterdir() if p.is_file()][:15]
                        parts.append(f"--- {fpath.relative_to(source_dir)}/ ---")
                        parts.extend(f"  {f}" for f in files)
                    else:
                        # Read small files (< 50KB)
                        size = fpath.stat().st_size
                        if size < 50_000:
                            content = fpath.read_text(errors="replace")
                            parts.append(f"--- {fpath.relative_to(source_dir)} ({size}b) ---")
                            parts.append(content[:2000])  # Limit per file
                except Exception as e:
                    parts.append(f"--- {fpath.relative_to(source_dir)}: error: {e} ---")

        return "\n".join(parts)
