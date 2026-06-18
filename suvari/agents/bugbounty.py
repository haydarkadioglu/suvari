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
        import threading, itertools, time, sys
        from rich.console import Console
        console = Console()
        console.print(f"  BugBounty: {url}")

        results = {}
        domain = url.split("://")[-1].split("/")[0]

        def spinner(stop, msg):
            for c in itertools.cycle(['/', '-', '\\', '|']):
                if stop():
                    break
                sys.stdout.write(f'\r  {msg} {c}')
                sys.stdout.flush()
                time.sleep(0.1)
            sys.stdout.write(f'\r  {msg} [OK]\n')
            sys.stdout.flush()

        # Phase 1
        stop = False
        t = threading.Thread(target=spinner, args=(lambda: stop, "Phase 1: Subdomain enumeration"))
        t.start()
        subdomains = self._enum_subdomains(domain)
        stop = True
        t.join()
        results["subdomains"] = subdomains

        # Phase 2
        stop = False
        t = threading.Thread(target=spinner, args=(lambda: stop, "Phase 2: URL discovery"))
        t.start()
        urls = self._discover_urls(domain)
        stop = True
        t.join()
        results["urls"] = urls

        # Phase 3
        stop = False
        t = threading.Thread(target=spinner, args=(lambda: stop, "Phase 3: Parameter discovery"))
        t.start()
        params = self._discover_params(url)
        stop = True
        t.join()
        results["params"] = params

        # Phase 4
        stop = False
        t = threading.Thread(target=spinner, args=(lambda: stop, "Phase 4: Technology"))
        t.start()
        tech = self._fingerprint_tech(url)
        stop = True
        t.join()
        results["technology"] = tech

        console.print(f"  Done: {len(subdomains)} subdomains, {len(urls)} URLs")
        return results

    def _enum_subdomains(self, domain: str) -> list:
        """Enumerate subdomains using available tools + DNS fallback."""
        found = set()

        # Method 1: subfinder
        if self.tools.check_tool("subfinder"):
            out = self.tools.run(["subfinder", "-silent", "-d", domain], timeout=60)
            for line in out.splitlines():
                line = line.strip()
                if line and not line.startswith("("):
                    found.add(line.lower())

        # Method 2: crt.sh Certificate Transparency logs (no tool needed)
        try:
            import urllib.request, json
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "Suvari/1.0"})
            resp = urllib.request.urlopen(req, timeout=15)
            data = json.loads(resp.read())
            for entry in data[:100]:
                name = entry.get("name_value", "").strip()
                if name and name.endswith(domain):
                    found.add(name.lower())
        except Exception:
            pass

        # Method 3: dnsenum (tight timeout)
        if self.tools.check_tool("dnsenum"):
            out = self.tools.run(["dnsenum", "--enum", domain, "--noreverse", "--timeout", "5"], timeout=20)
            for line in out.splitlines()[:50]:
                line = line.strip()
                if line and not line.startswith("(") and domain in line.lower():
                    found.add(line.lower().split()[-1])

        # Method 3: Fast DNS resolution via dig (faster than socket)
        common = ["www", "mail", "ftp", "admin", "api", "blog", "dev", "test",
                   "webmail", "remote", "vpn", "shop", "app", "beta", "m",
                   "ns1", "ns2", "mx", "cpanel", "dns", "server",
                   "support", "help", "cdn", "cloud", "portal", "secure",
                   "login", "docs", "git"]

        from concurrent.futures import ThreadPoolExecutor, as_completed
        import subprocess as sp

        def resolve_dig(sub):
            try:
                host = f"{sub}.{domain}"
                result = sp.run(["dig", "+short", "+time=2", "+tries=1", host],
                                capture_output=True, text=True, timeout=3)
                ip = result.stdout.strip()
                return host if ip else None
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=15) as pool:
            futures = {pool.submit(resolve_dig, sub): sub for sub in common}
            for fut in as_completed(futures):
                result = fut.result(timeout=4)
                if result:
                    found.add(result)

        # Verify results with HTTP check (filter out DNS wildcards)
        if self.tools.check_tool("httpx") and found:
            for sub in sorted(found)[:20]:
                for proto in ("https", "http"):
                    out = self.tools.run(["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code}",
                                          f"{proto}://{sub}", "--max-time", "4"], timeout=6)
                    code = out.strip()
                    if code not in ("000", "", "(error)", "(empty)"):
                        break

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
