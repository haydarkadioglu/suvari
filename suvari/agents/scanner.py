"""Scanner Agent — runs security scanning tools in parallel."""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseAgent, fmt_time


class ScannerAgent(BaseAgent):
    """Runs vulnerability scanning tools against the target."""

    def run(self, context: dict) -> dict:
        url = context.get("target_url", "")
        fast = context.get("fast", False)
        self.log(f"Scanning: {url} (fast={fast})")

        results = {}
        total_start = time.time()

        # Define scan tasks based on speed
        core_tools = [
            ("nuclei", ["nuclei", "-u", url, "-silent", "-severity", "low,medium,high,critical"], 120),
            ("nikto", ["nikto", "-h", url, "-nointeractive"], 120),
        ]
        if not fast:
            core_tools += [
                ("gobuster", ["gobuster", "dir", "-u", url, "-w", "/usr/share/wordlists/dirb/common.txt", "-q", "-t", "20"], 90),
                ("whatweb", ["whatweb", url, "--log-verbose=/dev/null"], 30),
            ]

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            for name, cmd, timeout in core_tools:
                if self.tools.check_tool(name.split("_")[0]):
                    t = time.time()
                    fut = executor.submit(self.tools.run, cmd, timeout)
                    futures[fut] = (name, t)
                else:
                    results[name] = "(not installed)"

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

        total = fmt_time(time.time() - total_start)
        self.log(f"Scan complete in {total}")
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