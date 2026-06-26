"""Scanner Agent — runs security scanning tools in parallel.

NOTE: Does NOT run recon tools (whatweb, nmap, curl headers, etc.)
Those are ReconAgent's job. Scanner focuses on vulnerability detection.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseAgent, fmt_time


# ── Tool definitions (category, cmd builder, timeout) ────────────────────────

# All available tools with categories, descriptions, and default timeouts
AVAILABLE_TOOLS = {
    "nuclei": {
        "category": "vuln",
        "desc": "Vulnerability scanner (4000+ templates)",
        "cmd": lambda url: ["nuclei", "-u", url, "-silent", "-severity", "low,medium,high,critical"],
        "timeout": 120,
    },
    "nikto": {
        "category": "vuln",
        "desc": "Web server scanner",
        "cmd": lambda url: ["nikto", "-h", url, "-nointeractive"],
        "timeout": 120,
    },
    "wafw00f": {
        "category": "info",
        "desc": "WAF fingerprinting",
        "cmd": lambda url: ["wafw00f", url],
        "timeout": 30,
    },
    "gobuster": {
        "category": "discovery",
        "desc": "Directory brute force",
        "cmd": lambda url: ["gobuster", "dir", "-u", url, "-w", "/usr/share/wordlists/dirb/common.txt", "-q", "-t", "20"],
        "timeout": 90,
    },
    "httpx": {
        "category": "info",
        "desc": "HTTP probing + tech detection",
        "cmd": lambda url: ["httpx", "-u", url, "-tech-detect", "-status-code", "-title", "-silent"],
        "timeout": 30,
    },
    "dalfox": {
        "category": "vuln",
        "desc": "XSS scanner",
        "cmd": lambda url: ["dalfox", "url", url, "--silence", "--only-custom-header"],
        "timeout": 60,
    },
    "ffuf": {
        "category": "discovery",
        "desc": "Web fuzzing",
        "cmd": lambda url: ["ffuf", "-u", f"{url}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-c", "-t", "20", "-s"],
        "timeout": 60,
    },
    "wpscan": {
        "category": "cms",
        "desc": "WordPress scanner",
        "cmd": lambda url: ["wpscan", "--url", url, "--no-update", "-e", "vp,vt,cb,dbe"],
        "timeout": 120,
    },
    "dnsrecon": {
        "category": "dns",
        "desc": "DNS reconnaissance",
        "cmd": lambda url: ["dnsrecon", "-d", url.split("://")[-1].split("/")[0]],
        "timeout": 30,
    },
}


# ── Output parsers ──────────────────────────────────────────────────────────

def parse_nuclei_output(text: str) -> dict:
    """Parse nuclei output into structured summary."""
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings = []
    for line in text.splitlines():
        line_s = line.strip()
        for sev in ("critical", "high", "medium", "low", "info"):
            if f"[{sev}]" in line_s.lower() or f"({sev})" in line_s.lower():
                summary[sev] += 1
                if len(findings) < 10:
                    findings.append(line_s[:200])
                break
    return {"severity_counts": summary, "total": sum(summary.values()), "top_findings": findings}


def parse_nikto_output(text: str) -> dict:
    """Count Nikto warnings/OSVDB entries."""
    findings = []
    osvdb_count = 0
    for line in text.splitlines():
        if "+ OSVDB" in line or "OSVDB-" in line:
            osvdb_count += 1
            if len(findings) < 10:
                findings.append(line.strip()[:200])
    return {"osvdb_count": osvdb_count, "top_findings": findings}


# ── Scanner Agent ───────────────────────────────────────────────────────────

class ScannerAgent(BaseAgent):
    """Runs vulnerability scanning tools against the target.
    
    NOTE: Does NOT run recon tools (whatweb, nmap, curl headers, etc.)
    Those are ReconAgent's job. Scanner focuses on vulnerability detection.
    """

    def run(self, context: dict) -> dict:
        url = context.get("target_url", "")
        fast = context.get("fast", False)
        recon_done = context.get("recon_done", [])
        self.log(f"Scanning: {url} (fast={fast})")

        results = {}
        total_start = time.time()

        # Select tools: skip any already used in recon
        core_tools = [
            t for t in [
                ("nuclei", AVAILABLE_TOOLS["nuclei"]),
                ("nikto", AVAILABLE_TOOLS["nikto"]),
                ("wafw00f", AVAILABLE_TOOLS["wafw00f"]),
            ]
            if t[0] not in recon_done and self.tools.check_tool(t[0])
        ]
        if not fast:
            for extra in ["gobuster", "httpx", "dalfox", "ffuf", "wpscan", "dnsrecon"]:
                if extra not in recon_done and self.tools.check_tool(extra):
                    core_tools.append((extra, AVAILABLE_TOOLS[extra]))

        if not core_tools:
            self.log("  No new tools to run (all already covered by recon)")
            results["_total_time"] = "0s"
            return results

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            for name, config in core_tools:
                t = time.time()
                fut = executor.submit(self.tools.run, config["cmd"](url), config["timeout"])
                futures[fut] = (name, t)

            for fut in as_completed(futures):
                name, submit_time = futures[fut]
                try:
                    output = fut.result()
                except Exception as e:
                    output = f"(error: {e})"
                elapsed = fmt_time(time.time() - submit_time)
                self.log(f"  {name} done in {elapsed}")
                self.ws.save_result("scan", name, output)
                results[name] = output

        # Build structured _summary from parsed output
        summary = {}
        if "nuclei" in results and isinstance(results["nuclei"], str):
            try:
                summary["nuclei"] = parse_nuclei_output(results["nuclei"])
            except Exception:
                pass
        if "nikto" in results and isinstance(results["nikto"], str):
            try:
                summary["nikto"] = parse_nikto_output(results["nikto"])
            except Exception:
                pass

        total = fmt_time(time.time() - total_start)
        self.log(f"Scan complete in {total}")
        results["_summary"] = summary
        results["_total_time"] = total
        return results


def parse_ai_tool_plan(text: str, available: dict) -> list:
    """Parse AI response to extract tool plan. JSON-first, then keyword fallback."""
    import json as _json

    cleaned = text.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned[6:]
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3].strip()
    if cleaned.startswith("json"):
        cleaned = cleaned[4:].strip()
    if cleaned.startswith("["):
        try:
            return _json.loads(cleaned)
        except _json.JSONDecodeError:
            pass

    # Keyword fallback
    text_lower = text.lower()
    tools_found = []
    avail_names = set(available.keys())

    # Priority order for scanning tools
    priority = ["nuclei", "nikto", "gobuster", "ffuf", "sqlmap", "wpscan",
                "httpx", "nmap", "curl", "hydra", "whatweb", "feroxbuster"]

    seen = set()
    for tool in priority:
        if tool not in available:
            continue
        if tool not in text_lower:
            continue
        if tool in seen:
            continue
        # Only include if it's a recommendation, not just a mention
        lines_with_tool = [l for l in text.split("\n") if tool in l.lower()]
        if not lines_with_tool:
            continue
        line = lines_with_tool[0].lower()

        # Extract args: look for flags after tool name
        args = []
        parts = line.replace("`", "").split()
        for i, p in enumerate(parts):
            if tool in p and i + 1 < len(parts):
                for arg in parts[i+1:]:
                    if arg.startswith("-"):
                        args.append(arg)
                    elif arg.startswith("http") or arg.startswith("/"):
                        args.extend(["-u", arg])
                    elif len(args) > 5:
                        break

        reason_match = __import__('re').search(rf'{tool}[^.]*\.([^.]*)', text)
        reason = reason_match.group(1).strip()[:100] if reason_match else f"Recommended for target"
        tools_found.append({"tool": tool, "args": args[:5], "reason": reason})
        seen.add(tool)

    return tools_found[:10]