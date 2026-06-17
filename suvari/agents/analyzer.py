"""
Analyzer Agent — AI-powered analysis of scan results.
Inspired by Shannon's vulnerability analysis pipeline.
"""

import time
from .base import BaseAgent, fmt_time
from ..prompt_loader import PromptLoader


class AnalyzerAgent(BaseAgent):
    """AI analysis of scan results — identifies real vulnerabilities."""

    def run(self, context: dict) -> dict:
        url = context["target_url"]
        recon_results = context.get("recon_results", {})
        scan_results = context.get("scan_results", {})
        fast = context.get("fast", False)

        self.log("🧠 AI analyzing results...")

        recon_text = "\n\n".join([
            f"=== {k} ===\n{v[:2000]}"
            for k, v in recon_results.items()
            if isinstance(v, str)
        ])

        scan_text = "\n\n".join([
            f"=== {k} ===\n{v[:4000]}"
            for k, v in scan_results.items()
            if isinstance(v, str)
        ])

        # Load prompt from file
        loader = PromptLoader(url, fast)
        prompt_ctx = {
            "recon_data": recon_text[:4000],
            "scan_data": scan_text[:8000],
        }
        if context.get("analysis_context"):
            prompt_ctx["analysis_context"] = context["analysis_context"]
        system_prompt = loader.render_with_shared("analyzer", **prompt_ctx)

        self.log("  🛠️  LLM — AI vulnerability analysis")
        t0 = time.time()

        try:
            analysis = self.llm.chat_json(
                messages=[{"role": "user", "content": system_prompt}],
                temperature=0.1,
            )
            elapsed = fmt_time(time.time() - t0)
            self.ws.save_json("analysis", "findings", analysis)
            summary = analysis.get("summary", {})
            self.log(f"     ✅ Analysis done in {elapsed} — {summary.get('total', 0)} findings")
            return analysis
        except Exception as e:
            self.log(f"  ⚠️ Analysis error: {e}")
            return {
                "vulnerabilities": [],
                "error": str(e),
                "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            }
