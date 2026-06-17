"""
Recon Agent — gathers information about the target.
Parallel execution for speed, shows real-time elapsed time.
"""

import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse
from .base import BaseAgent, fmt_time


def clean_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.fragment:
        parsed = parsed._replace(fragment="")
        return urlunparse(parsed)
    return url


SOURCE_FILES = [
    "package.json", "requirements.txt", "Pipfile", "Gemfile",
    "composer.json", "go.mod", "Cargo.toml",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env.example", ".env", "config.js", "config.py",
    "app.js", "app.py", "index.js", "server.js", "main.py",
    "routes/", "controllers/", "api/", "middleware/",
]


class ReconAgent(BaseAgent):
    """Gathers target information in parallel: technology, ports, headers, source code."""

    def run(self, context: dict) -> dict:
        url = clean_url(context["target_url"])
        self.log(f" Reconnaissance: {url}")

        results = {}
        total_start = time.time()

        # Run independent tasks in parallel
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}

            # 1. whatweb
            if self.tools.check_tool("whatweb"):
                futures[executor.submit(self.tools.run, ["whatweb", url], 30)] = "whatweb"
            else:
                results["whatweb"] = "(not installed)"

            # 2. curl headers
            futures[executor.submit(self.tools.run, ["curl", "-sI", "-L", url, "--max-time", "10"], 15)] = "headers"

            # 3. nmap
            if self.tools.check_tool("nmap"):
                host = url.split("://")[-1].split("/")[0]
                is_server = context.get("server_scan", False)
                if is_server:
                    nmap_cmd = ["nmap", "-sV", "--top-ports", "1000", "--open", host]
                    futures[executor.submit(self.tools.run, nmap_cmd, 180)] = "nmap"
                else:
                    nmap_cmd = ["nmap", "-T4", "-F", "--open", host]
                    futures[executor.submit(self.tools.run, nmap_cmd, 60)] = "nmap"
            else:
                results["nmap"] = "(not installed)"

            # 4. robots.txt + common paths (combined curl check)
            futures[executor.submit(self.tools.run, ["curl", "-sL", f"{url.rstrip('/')}/robots.txt", "--max-time", "8"], 12)] = "robots"

            # Collect results as they complete
            for fut in as_completed(futures):
                name = futures[fut]
                t1 = time.time()
                try:
                    output = fut.result()
                except Exception as e:
                    output = f"(error: {e})"
                elapsed = fmt_time(time.time() - t1)

                if name == "whatweb":
                    self.log(f"  whatweb done in {elapsed}")
                elif name == "headers":
                    self.log(f"  headers done in {elapsed}")
                elif name == "nmap":
                    self.log(f"  nmap done in {elapsed}")
                elif name == "robots":
                    self.log(f"  robots done in {elapsed}")

                self.ws.save_result("recon", name, output)
                results[name] = output

            # 5. Common paths (sequential, fast)
            t0 = time.time()
            common_paths = ["/.git/config", "/.env", "/sitemap.xml", "/crossdomain.xml"]
            findings = []
            for path in common_paths:
                out = self.tools.run(
                    ["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code}",
                     f"{url.rstrip('/')}{path}", "--max-time", "4"], timeout=8
                )
                if out.strip() not in ("404", "301", "302", "403", "(error)", "(empty)"):
                    findings.append(f"{path}: {out.strip()}")
            results["common_paths"] = "\n".join(findings) if findings else "No exposed files found"
            self.log(f"  path check done in {fmt_time(time.time() - t0)}")

        # 6. White-box: read source code if available
        source_dir = context.get("source_dir")
        if source_dir:
            self.log(f"  source — Reading: {source_dir}")
            t0 = time.time()
            source_info = self._read_source_code(Path(source_dir))
            if source_info:
                self.ws.save_result("recon", "source_analysis", source_info)
                results["source_analysis"] = source_info
                lines = source_info.count("\n")
                self.log(f"  source done in {fmt_time(time.time() - t0)} ({lines} lines)")

        total = fmt_time(time.time() - total_start)
        self.log(f"Recon complete in {total}")
        results["_recon_time"] = total
        results["_target"] = url
        return results

    def _read_source_code(self, source_dir: Path) -> str:
        if not source_dir.exists():
            return ""
        parts = [f"=== Source: {source_dir} ===\n"]
        for pattern in SOURCE_FILES:
            for fpath in list(source_dir.rglob(pattern))[:5]:
                try:
                    if fpath.is_dir():
                        files = [p.name for p in fpath.iterdir() if p.is_file()][:15]
                        parts.append(f"--- {fpath.relative_to(source_dir)}/ ---")
                        parts.extend(f"  {f}" for f in files)
                    else:
                        size = fpath.stat().st_size
                        if size < 50_000:
                            content = fpath.read_text(errors="replace")
                            parts.append(f"--- {fpath.relative_to(source_dir)} ({size}b) ---")
                            parts.append(content[:2000])
                except Exception:
                    pass
        return "\n".join(parts)
