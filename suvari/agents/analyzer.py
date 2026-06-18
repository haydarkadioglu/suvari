"""
Analyzer Agent — AI-powered analysis of scan results with robust text parsing.
Shows clear errors when AI is unavailable.
"""

import time
import re
import json
from .base import BaseAgent, fmt_time
from ..prompt_loader import PromptLoader


class AnalyzerAgent(BaseAgent):
    """AI analysis of scan results — extracts vulnerabilities from plain text."""

    def run(self, context: dict) -> dict:
        url = context["target_url"]
        recon_results = context.get("recon_results", {})
        scan_results = context.get("scan_results", {})
        browser_info = context.get("browser_info", {})
        cve_findings = context.get("cve_findings", [])
        jwt_findings = context.get("jwt_findings", [])
        fast = context.get("fast", False)

        self.log("[AI] AI analyzing results...")

        recon_text = "\n\n".join([
            f"=== {k} ===\n{v[:2000]}"
            for k, v in recon_results.items() if isinstance(v, str)
        ])
        scan_text = "\n\n".join([
            f"=== {k} ===\n{v[:4000]}"
            for k, v in scan_results.items() if isinstance(v, str)
        ])

        extra = ""
        if browser_info:
            extra += f"\n\nBrowser: {browser_info.get('title','')} | Tech: {browser_info.get('tech',[])}"
        if cve_findings:
            for c in cve_findings[:3]:
                extra += f"\nCVE: {c.get('cve_id','?')} ({c.get('cvss','')}) - {c.get('description','')[:100]}"
        if jwt_findings:
            for j in jwt_findings[:3]:
                extra += f"\nJWT: {j.get('type','')}"

        loader = PromptLoader(url, fast)
        prompt_ctx = {"recon_data": recon_text[:4000], "scan_data": scan_text[:8000]}
        if extra:
            prompt_ctx["analysis_context"] = extra
        system_prompt = loader.render_with_shared("analyzer", **prompt_ctx)

        self.log("  [TOOL] LLM — AI vulnerability analysis")
        t0 = time.time()

        try:
            response = self.llm.chat(
                messages=[{"role": "user", "content": system_prompt}],
                temperature=0.1,
                max_tokens=2048,
            )
        except Exception as api_err:
            self.log(f"[AI UNAVAILABLE] {api_err}")
            self.log("[AI UNAVAILABLE] Scan completed without AI analysis. Check API key.")
            return {
                "vulnerabilities": [],
                "error": str(api_err),
                "ai_available": False,
                "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            }

        vulnerabilities = self._extract_vulnerabilities(response, url)
        elapsed = fmt_time(time.time() - t0)

        sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulnerabilities:
            s = v.get("severity", "low").lower()
            if s in sev_count:
                sev_count[s] += 1

        result = {
            "vulnerabilities": vulnerabilities,
            "summary": {"total": len(vulnerabilities), **sev_count},
            "raw_analysis": response[:1000],
        }
        self.ws.save_json("analysis", "findings", result)
        self.log(f"     [OK] Analysis done in {elapsed} — {len(vulnerabilities)} findings")
        return result

    def _extract_vulnerabilities(self, text: str, target_url: str) -> list:
        """Extract vulnerabilities from AI's plain text response."""
        vulns = []

        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()
        if cleaned.startswith("json"):
            cleaned = cleaned[4:].strip()
        if cleaned.startswith("{"):
            try:
                data = json.loads(cleaned)
                if "vulnerabilities" in data:
                    return data["vulnerabilities"]
            except json.JSONDecodeError:
                pass

        lines = text.split("\n")
        severity_indicators = {
            "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
            "LOW": "LOW", "INFO": "INFO",
        }

        for line in lines:
            line = line.strip()
            if not line:
                continue
            for indicator, sev in severity_indicators.items():
                if indicator in line:
                    parts = line.split(":", 1) if ":" in line else [line, ""]
                    vulns.append({
                        "severity": sev,
                        "type": parts[0].strip()[:80],
                        "location": parts[1].strip()[:120] if len(parts) > 1 else target_url,
                        "description": line[:200],
                    })
                    break
            if line.startswith("- ") and ":" in line:
                left, right = line[2:].split(":", 1)
                vulns.append({
                    "severity": "MEDIUM",
                    "type": left.strip()[:80],
                    "location": right.strip()[:120],
                    "description": line[:200],
                })

        return vulns[:20]
