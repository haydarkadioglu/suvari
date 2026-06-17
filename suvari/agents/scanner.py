"""
Scanner Agent — AI-driven vulnerability scanning with parallel execution + failure recovery.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse
from .base import BaseAgent, fmt_time
from ..prompt_loader import PromptLoader
from ..mode import ScanMode
from ..failure import classify_failure, get_recovery_strategy, FailureLevel


def clean_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.fragment:
        parsed = parsed._replace(fragment="")
        return urlunparse(parsed)
    return url


def build_cmd(tool_name: str, args: list, url: str) -> list:
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


def build_fallback_cmd(alt_tool: str, url: str) -> list:
    """Build command for a fallback tool."""
    if alt_tool in ("masscan", "rustscan"):
        host = url.split("://")[-1].split("/")[0]
        return [alt_tool, "--rate", "1000", host] if alt_tool == "masscan" else [alt_tool, "-a", host]
    return build_cmd(alt_tool, ["-silent", "-severity", "medium"], url) if alt_tool == "nuclei" else [alt_tool, url]


class ScannerAgent(BaseAgent):
    """AI-driven vulnerability scanning with failure recovery and fallback tools."""

    TOOL_MAX_TIMES = {
        "nuclei": 120, "nikto": 150, "gobuster": 90, "ffuf": 90,
        "sqlmap": 210, "wpscan": 150, "httpx": 30, "curl": 15, "nmap": 90,
    }

    def run(self, context: dict) -> dict:
        url = clean_url(context["target_url"])
        recon_results = context.get("recon_results", {})
        fast = context.get("fast", False)
        user_suggestions = context.get("user_suggestions", "")
        server_scan = context.get("server_scan", False)
        parallel = context.get("parallel", 3)

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
            tool_plan = plan if isinstance(plan, list) else plan.get("tools", [])
            strategy = plan.get("strategy", "") if isinstance(plan, dict) else ""
            self.log(f"  Plan ready ({fmt_time(time.time() - t0)}): {[t.get('tool','?') for t in tool_plan]}")
        except Exception as e:
            self.log(f"  AI plan error: {e}, fallback")
            tool_plan = [{"tool": "nuclei", "args": ["-silent", "-severity", "critical,high,medium"], "reason": "Fallback"}]

        max_tools = 3 if fast else 5
        tool_plan = tool_plan[:max_tools]
        tool_plan = [t for t in tool_plan if t.get("tool") in avail]
        if not tool_plan and "nuclei" in avail:
            tool_plan = [{"tool": "nuclei", "args": ["-silent", "-severity", "critical,high,medium"], "reason": "Fallback"}]

        results = {}
        total_start = time.time()

        tasks = [(item["tool"], build_cmd(item["tool"], item.get("args", []), url),
                  item.get("timeout", self.TOOL_MAX_TIMES.get(item["tool"], 60)),
                  item.get("reason", "")) for item in tool_plan]

        self.log(f"  Running {len(tasks)} tools ({parallel} at a time)...")

        with ThreadPoolExecutor(max_workers=parallel) as executor:
            future_map = {executor.submit(self._run_with_fallback, tn, cmd, mt, reason, url): tn
                          for tn, cmd, mt, reason in tasks}
            for fut in as_completed(future_map):
                tool_name, output, elapsed_str, status = fut.result()
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

    def _run_with_fallback(self, tool_name: str, cmd: list, max_time: int, reason: str, url: str) -> tuple:
        """Run a tool with failure classification and fallback support."""
        t0 = time.time()
        output = self.tools.run(cmd, timeout=max_time)
        elapsed = time.time() - t0
        elapsed_str = fmt_time(elapsed)

        level, fail_reason = classify_failure(output, tool_name)
        strategy = get_recovery_strategy(level, tool_name)

        if level == FailureLevel.L0_OBSERVATION:
            return (tool_name, output, elapsed_str, "OK")

        # L1/L2/L3: retryable, try fallback
        if level.retryable and strategy["fallback_tools"]:
            for alt_tool in strategy["fallback_tools"]:
                if self.tools.check_tool(alt_tool):
                    alt_cmd = build_fallback_cmd(alt_tool, url)
                    t1 = time.time()
                    alt_out = self.tools.run(alt_cmd, timeout=max_time)
                    if alt_out and not alt_out.startswith("("):
                        return (tool_name, alt_out, fmt_time(time.time() - t1), f"OK(fb:{alt_tool})")

        # Non-retryable or no fallback worked
        status = f"{level.value}:{fail_reason[:25]}"
        return (tool_name, output, elapsed_str, status)
