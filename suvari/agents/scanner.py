"""
Scanner Agent — AI-driven vulnerability scanning with parallel execution + failure recovery.
Uses plain-text AI response (no JSON dependency) for robustness.
"""

import time
import re
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
    if tool_name in ("nuclei", "gobuster", "ffuf", "sqlmap", "httpx"):
        cmd += ["-u", url]
    elif tool_name in ("nikto", "curl"):
        cmd += [url]
    elif tool_name == "wpscan":
        cmd += ["--url", url]
    elif tool_name == "nmap":
        cmd += [url.split("://")[-1].split("/")[0]]
    return cmd


def parse_ai_tool_plan(text: str, available: dict) -> list:
    """Parse AI response to extract tool plan. No JSON dependency."""
    text_lower = text.lower()
    tools_found = []

    # Look for known tool names in order they appear
    tool_order = ["nuclei", "nikto", "gobuster", "ffuf", "sqlmap", "wpscan",
                  "httpx", "nmap", "curl", "hydra", "whatweb"]

    for tool in tool_order:
        if tool not in available:
            continue
        # Check if tool is mentioned (by name)
        if tool in text_lower:
            # Try to extract args - look for text between tool name and next tool
            args = re.findall(rf'{tool}[^.]*?[-][a-z]\S+', text_lower[:500])
            parsed_args = args[0].split() if args else []
            # Filter to only real flags
            parsed_args = [a for a in parsed_args if a.startswith("-")][:5]

            reason_match = re.search(rf'{tool}[^.]*\.([^.]*)', text)
            reason = reason_match.group(1).strip()[:100] if reason_match else f"AI recommended {tool}"

            tools_found.append({
                "tool": tool,
                "args": parsed_args,
                "reason": reason,
            })

    # Limit based on text mentions (more mentions = higher priority)
    tools_found = tools_found[:5]
    return tools_found


class ScannerAgent(BaseAgent):
    """AI-driven vulnerability scanning with plain-text AI (no JSON)."""

    TOOL_MAX_TIMES = {
        "nuclei": 120, "nikto": 150, "gobuster": 90, "ffuf": 90,
        "sqlmap": 210, "wpscan": 150, "httpx": 30, "curl": 15, "nmap": 90,
    }

    def run(self, context: dict) -> dict:
        url = clean_url(context["target_url"])
        recon_results = context.get("recon_results", {})
        fast = context.get("fast", False)
        parallel = context.get("parallel", 3)

        self.log(f" Scanning: {url}")

        recon_text = "\n\n".join([
            f"=== {k} ===\n{v[:1500]}"
            for k, v in recon_results.items()
            if isinstance(v, str) and v and not v.startswith("(")
        ])

        avail = self.tools.available_tools()

        loader = PromptLoader(url, fast)
        prompt = loader.render_with_shared("scanner",
            recon_data=recon_text[:4000], available_tools=avail,
            server_scan=context.get("server_scan", False))

        self.log(f"  AI planning...")
        t0 = time.time()
        try:
            # Plain text AI (no JSON)
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=512,
            )
            tool_plan = parse_ai_tool_plan(response, avail)
            self.log(f"  Plan ready ({fmt_time(time.time() - t0)}): {[t['tool'] for t in tool_plan]}")
        except Exception as e:
            self.log(f"  AI plan error: {e}, fallback")
            tool_plan = [{"tool": "nuclei", "args": ["-silent", "-severity", "critical,high,medium"], "reason": "Fallback"}]

        max_tools = 5 if fast else 10
        tool_plan = tool_plan[:max_tools]
        if not tool_plan and "nuclei" in avail:
            tool_plan = [{"tool": "nuclei", "args": ["-silent", "-severity", "critical,high,medium"], "reason": "Fallback"}]

        results = {}
        total_start = time.time()

        tasks = [(item["tool"], build_cmd(item["tool"], item.get("args", []), url),
                  self.TOOL_MAX_TIMES.get(item["tool"], 60), item.get("reason", ""))
                 for item in tool_plan]

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
        """Run a tool with failure classification and fallback."""
        t0 = time.time()
        output = self.tools.run(cmd, timeout=max_time)
        elapsed = time.time() - t0
        elapsed_str = fmt_time(elapsed)

        level, fail_reason = classify_failure(output, tool_name)
        strategy = get_recovery_strategy(level, tool_name)

        if level == FailureLevel.L0_OBSERVATION:
            return (tool_name, output, elapsed_str, "OK")

        if level.retryable and strategy["fallback_tools"]:
            for alt_tool in strategy["fallback_tools"]:
                if self.tools.check_tool(alt_tool):
                    alt_cmd = build_cmd(alt_tool, ["-silent"], url)
                    t1 = time.time()
                    alt_out = self.tools.run(alt_cmd, timeout=max_time)
                    if alt_out and not alt_out.startswith("("):
                        return (tool_name, alt_out, fmt_time(time.time() - t1), f"OK(fb:{alt_tool})")

        status = f"{level.value}:{fail_reason[:25]}"
        return (tool_name, output, elapsed_str, status)
