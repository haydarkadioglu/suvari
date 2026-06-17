"""
Scanner Agent — AI-driven vulnerability scanning with parallel execution.
AI picks tools, runs them in parallel for speed.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse
from .base import BaseAgent, fmt_time
from ..prompt_loader import PromptLoader
from ..mode import ScanMode


def clean_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.fragment:
        parsed = parsed._replace(fragment="")
        return urlunparse(parsed)
    return url


def build_cmd(tool_name: str, args: list, url: str) -> list:
    """Build command list."""
    cmd = [tool_name] + args
    if tool_name in ("nuclei", "gobuster", "ffuf", "sqlmap"):
        cmd += ["-u", url]
    elif tool_name in ("nikto", "curl"):
        cmd += [url]
    elif tool_name == "wpscan":
        cmd += ["--url", url]
    elif tool_name == "httpx":
        cmd = [tool_name, "-u", url]
    elif tool_name == "nmap":
        cmd += [url.split("://")[-1].split("/")[0]]
    return cmd


class ScannerAgent(BaseAgent):
    """Vulnerability scanning — AI decides tools, runs them in parallel."""

    TOOL_MAX_TIMES = {
        "nuclei": 120, "nikto": 150, "gobuster": 90,
        "ffuf": 90, "sqlmap": 210, "wpscan": 150,
        "httpx": 30, "curl": 15, "nmap": 90,
    }

    def run(self, context: dict) -> dict:
        url = clean_url(context["target_url"])
        recon_results = context.get("recon_results", {})
        fast = context.get("fast", False)
        user_suggestions = context.get("user_suggestions", "")
        server_scan = context.get("server_scan", False)
        parallel = context.get("parallel", 3)  # Default 3 parallel tools

        self.log(f" Scanning: {url}")

        recon_text = "\n\n".join([
            f"=== {k} ===\n{v[:1500]}"
            for k, v in recon_results.items()
            if isinstance(v, str) and v and not v.startswith("(")
        ])

        avail = self.tools.available_tools()

        loader = PromptLoader(url, fast)
        prompt_ctx = {"recon_data": recon_text[:4000], "available_tools": avail, "server_scan": server_scan}
        if user_suggestions:
            prompt_ctx["user_suggestions"] = user_suggestions
        prompt = loader.render_with_shared("scanner", **prompt_ctx)

        self.log(f"  AI planning...")
        t0 = time.time()
        try:
            plan = self.llm.chat_json(messages=[{"role": "user", "content": prompt}], temperature=0.2)
            plan_time = fmt_time(time.time() - t0)
            tool_plan = plan if isinstance(plan, list) else plan.get("tools", [])
            strategy = plan.get("strategy", "") if isinstance(plan, dict) else ""
            if strategy:
                self.log(f"  Strategy: {strategy[:120]}")
            self.log(f"  Plan ready ({plan_time}): {[t.get('tool','?') for t in tool_plan]}")
        except Exception as e:
            self.log(f"  AI plan error: {e}, fallback to nuclei")
            tool_plan = [{"tool": "nuclei", "args": ["-silent", "-severity", "critical,high,medium"],
                         "reason": "Fallback"}]

        max_tools = 3 if fast else 5
        tool_plan = tool_plan[:max_tools]
        tool_plan = [t for t in tool_plan if t.get("tool") in avail]

        if not tool_plan:
            self.log("  No tools, using nuclei fallback")
            if "nuclei" in avail:
                tool_plan = [{"tool": "nuclei", "args": ["-silent", "-severity", "critical,high,medium"],
                             "reason": "Fallback"}]

        results = {}
        total_start = time.time()

        # Build all tasks first
        tasks = []
        for item in tool_plan:
            tool_name = item["tool"]
            args = item.get("args", [])
            reason = item.get("reason", "")
            max_time = self.TOOL_MAX_TIMES.get(tool_name, 60)
            cmd = build_cmd(tool_name, args, url)
            tasks.append((tool_name, cmd, max_time, reason))

        # Run in parallel
        self.log(f"  Running {len(tasks)} tools (up to {parallel} at a time)...")
        with ThreadPoolExecutor(max_workers=parallel) as executor:
            future_map = {}
            for tool_name, cmd, max_time, reason in tasks:
                self.log(f"    {tool_name} — {reason[:60]}")
                fut = executor.submit(self.tools.run, cmd, max_time)
                future_map[fut] = (tool_name, cmd, max_time)

            for fut in as_completed(future_map):
                tool_name, cmd, max_time = future_map[fut]
                t1 = time.time()
                try:
                    output = fut.result(timeout=max_time + 10)
                except Exception as e:
                    output = f"(executor error: {e})"
                elapsed = time.time() - t1
                elapsed_str = fmt_time(elapsed)

                if "TIMEOUT" in output:
                    status = "TIMEOUT"
                elif output.startswith("("):
                    status = f"ERROR:{output[1:25]}"
                else:
                    status = "OK"

                self.log(f"     [{status}] {tool_name} ({elapsed_str})")
                if status != "OK":
                    preview = output[:100].replace("\n", " ").strip()
                    self.log(f"       -> {preview}")

                self.ws.save_result("scans", tool_name, output)
                results[tool_name] = output
                results[f"{tool_name}_time"] = elapsed_str
                results[f"{tool_name}_status"] = status

        total_time = fmt_time(time.time() - total_start)
        self.log(f"Scan complete in {total_time}")
        results["_total_time"] = total_time
        return results
