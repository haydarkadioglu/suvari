"""
Scanner Agent — AI-driven vulnerability scanning.
AI analyzes recon data and decides which tools to run.
"""

import time
from urllib.parse import urlparse, urlunparse
from .base import BaseAgent, fmt_time
from ..prompt_loader import PromptLoader
from ..mode import ScanMode, ask_user


def clean_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.fragment:
        parsed = parsed._replace(fragment="")
        return urlunparse(parsed)
    return url


class ScannerAgent(BaseAgent):
    """Vulnerability scanning — AI decides which tools to use."""

    TOOL_MAX_TIMES = {
        "nuclei": 120, "nikto": 150, "gobuster": 90,
        "ffuf": 90, "sqlmap": 210, "wpscan": 150,
        "httpx": 30, "curl": 15, "nmap": 90,
    }

    def run(self, context: dict) -> dict:
        url = clean_url(context["target_url"])
        recon_results = context.get("recon_results", {})
        fast = context.get("fast", False)
        mode = context.get("mode", ScanMode.GUIDED)
        user_suggestions = context.get("user_suggestions", "")
        server_scan = context.get("server_scan", False)

        self.log(f" Scanning: {url}")

        recon_text = "\n\n".join([
            f"=== {k} ===\n{v[:1500]}"
            for k, v in recon_results.items()
            if isinstance(v, str) and v and not v.startswith("(")
        ])

        avail = self.tools.available_tools()

        # AI picks the tools
        loader = PromptLoader(url, fast)
        prompt_ctx = {"recon_data": recon_text[:4000], "available_tools": avail, "server_scan": server_scan}
        if user_suggestions:
            prompt_ctx["user_suggestions"] = user_suggestions
        prompt = loader.render_with_shared("scanner", **prompt_ctx)

        self.log(f"  AI planning tool selection...")
        t0 = time.time()

        try:
            plan = self.llm.chat_json(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2)
            plan_time = fmt_time(time.time() - t0)
            tool_plan = plan if isinstance(plan, list) else plan.get("tools", [])
            strategy = plan.get("strategy", "") if isinstance(plan, dict) else ""
            if strategy:
                self.log(f"  Strategy: {strategy[:120]}")
            self.log(f"  AI plan ready ({plan_time}): {[t.get('tool','?') for t in tool_plan]}")
        except Exception as e:
            self.log(f"  AI plan error: {e}, using fallback")
            tool_plan = [{"tool": "nuclei", "args": ["-silent", "-severity", "critical,high,medium"],
                         "reason": "Fallback: broad CVE scan"}]

        max_tools = 3 if fast else 5
        tool_plan = tool_plan[:max_tools]
        tool_plan = [t for t in tool_plan if t.get("tool") in avail]

        if not tool_plan:
            self.log("  No suitable tools from AI, using nuclei fallback")
            if "nuclei" in avail:
                tool_plan = [{"tool": "nuclei", "args": ["-silent", "-severity", "critical,high,medium"],
                             "reason": "Emergency fallback"}]

        # Run tools
        results = {}
        total_start = time.time()

        for item in tool_plan:
            tool_name = item["tool"]
            args = item.get("args", [])
            reason = item.get("reason", "")
            max_time = self.TOOL_MAX_TIMES.get(tool_name, 60)

            # Interactive/guided mode questions
            if mode == ScanMode.INTERACTIVE:
                self.log(f"  {tool_name} — {reason[:80]}")
                ans = input(f"     Run {tool_name}? [Y/n] ").strip().lower()
                if ans in ("n", "no"):
                    self.log(f"     Skipped")
                    results[tool_name] = "(skipped)"
                    results[f"{tool_name}_time"] = "skipped"
                    results[f"{tool_name}_status"] = "SKIPPED"
                    continue
            elif max_time > 30 and mode.suggestions_enabled:
                self.log(f"  {tool_name} — {reason[:80]}")
                self.log(f"     (estimated: up to {max_time}s)")
                if not ask_user(f"Run {tool_name} (~{max_time}s)?", default=False):
                    self.log(f"     Skipped")
                    results[tool_name] = "(skipped)"
                    results[f"{tool_name}_time"] = "skipped"
                    results[f"{tool_name}_status"] = "SKIPPED"
                    continue

            # Build command with tool name FIRST
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

            # Execute
            self.log(f"  {tool_name} — {reason[:80]}")
            t0 = time.time()
            output = self.tools.run(cmd, timeout=max_time)
            elapsed = time.time() - t0
            elapsed_str = fmt_time(elapsed)

            if "TIMEOUT" in output:
                status = "TIMEOUT"
            elif output.startswith("("):
                status = f"ERROR:{output[1:25]}"
            else:
                status = "OK"

            self.log(f"     [{status}] {tool_name} ({elapsed_str})")
            if status != "OK":
                out_preview = output[:100].replace("\n", " ").strip()
                self.log(f"     -> {out_preview}")

            self.ws.save_result("scans", tool_name, output)
            results[tool_name] = output
            results[f"{tool_name}_time"] = elapsed_str
            results[f"{tool_name}_status"] = status

        total_time = fmt_time(time.time() - total_start)
        self.log(f"Scan complete in {total_time}")
        results["_total_time"] = total_time
        return results
